#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-only

# **** License ****
#
# Copyright (c) 2018-2020, AT&T Intellectual Property.
# All Rights Reserved.
#
# License:
#
# This software is licensed, and not freely redistributable. See the
# subscription license agreement for details.
#
# **** End License ****

# The folowing script does:
#   - Update grub.cfg with a grub superuser and accompanying password.
#   - Populate vyatta config boot-loader superuser and password nodes
#

use strict;
use warnings;
use lib "/opt/vyatta/share/perl5";

use Vyatta::Configd;
use Vyatta::Live;
use Getopt::Long;
use XorpConfigParser;

my $configd = Vyatta::Configd::Client->new();
my $db      = $Vyatta::Configd::Client::AUTO;

my $grub_cfg           = '/boot/grub/grub.cfg';
my $grub_template      = '/opt/vyatta/etc/grub/default-union-grub.template';
my $grub_onie_cfg      = '/boot/grub-master/boot/grub/grub.cfg';
my $grub_onie_template = '/opt/vyatta/etc/grub/grub-onie.template';

my $cfg_file = '/config/config.boot';

my $pt_enable = 'iommu=pt ';

sub gen_pass {
    my $p = shift;
    my $pbkdf2 =
`yes "$p" 2>/dev/null | grub-mkpasswd-pbkdf2 | tail -n 1 | grep -o grub\.pbkdf2.*`;
    chomp($pbkdf2);
    return $pbkdf2;
}

# Should only be called by on the first system install (i.e. install image), if at all.
#
sub create_vyatta_config_grub_options {
    my ( $u, $p, $c ) = @_;

    my $gen_pass = gen_pass($p);
    my $xcp      = new XorpConfigParser();
    $xcp->parse($c);

    if ( $xcp->node_exists("system boot-loader user $u") ) {
        die __FILE__ . ": Grub user node for user $u alredy exists.\n";
    }
    if ( $xcp->node_exists("system boot-loader user $u encrypted-password") ) {
        die __FILE__ . ": Grub password node for user $u alredy exists.\n";
    }

    $xcp->create_node( [ 'system', 'boot-loader' ] );
    my $user = $xcp->get_node( [ 'system', 'boot-loader' ] );
    $user->{'children'} = [
        {
            'name'     => "user $u",
            'value'    => undef,
            'children' => [
                {
                    'name'  => 'encrypted-password',
                    'value' => $gen_pass,
                }
            ]
        }
    ];

    my $CFGFILE;
    open $CFGFILE, ">$c";
    select $CFGFILE;
    $xcp->output(0);
}

sub vga_is_present {
    return ( qx(lspci 2> /dev/null) =~ /VGA/ );
}

sub build_grub_cmd {
    my ( $reduced, $index, $grub_users, $gcfg, $gtemplate, $pt_cmd, @images ) =
      (@_);
    if ( $index eq "" ) {
        die __FILE__ . ": Missing input: \$index.\n";
    }
    if ( $reduced eq "" ) {
        $reduced = 0;
    }
    if ( $gcfg eq "" ) {
        $gcfg = $grub_cfg;
    }
    if ( $gtemplate eq "" ) {
        $gtemplate = $grub_template;
    }

    my $gen_image_cfg = sub {
        my ($e) = @_;
        if ( $e eq "" ) {
            return;
        }
        my $out = { "image-name" => $e, };
        return $out;
    };
    my @out = map { $gen_image_cfg->($_) } @images;

    my $global->{'reduced'} = $reduced;
    $global->{'date'}    = localtime();
    $global->{'default'} = $index;
    $global->{'pt-cmd'}  = $pt_cmd;

    # If no VGA in system, 1st serial port automatically becomes the console
    $global->{'append-serial'} = vga_is_present() ? 'yes' : 'no';

    if ( $grub_users ne '' ) {
        $global->{'ubac'}       = 'yes';
        $global->{'grub-users'} = $grub_users;
    }

    open( my $fh, '<', $gtemplate );
    my $template = Template->new();
    my %tree_in = ( 'images' => \@out, 'global' => $global );
    $template->process( $fh, \%tree_in, $gcfg )
      or die __FILE__ . ": Could not fill out Grub template\n";
    close($fh);

    # Try and clean up a bit...
    system("cat -s $gcfg > /tmp/.grub_tmp");
    rename "/tmp/.grub_tmp", "$gcfg";
}

sub build_onie_cmd {
    my ( $console, $console_speed, $grub_users, $t, $c ) = (@_);

    my $global;
    if ( $console =~ m/ttyS?(\d)*/ ) {
        $global->{'console'} = $1;
    }
    else {
        $global->{'console'} = 0;
    }

    $global->{'console-speed'} = $console_speed;

    if ( $grub_users ne '' ) {
        $global->{'ubac'}       = 'yes';
        $global->{'grub-users'} = $grub_users;
    }

    $global->{'efi'} = ( -d "/sys/firmware/efi" ) ? "yes" : "no";

    open( my $fh, '<', $t );
    my $template = Template->new();
    my %tree_in = ( 'global' => $global );
    $template->process( $fh, \%tree_in, $c )
      or die __FILE__ . ": Could not fill out Grub ONIE template\n";
    close($fh);

    # Try and clean up a bit...
    system("cat -s $c > /tmp/.grub_tmp");
    rename "/tmp/.grub_tmp", "$c";
}

sub generate_grub_cmd {
    my ($image) = (@_);

    if ( !is_installed_system() ) {
        die __FILE__
          . ": rebuild_grub can only be run on an installed system.\n";
    }

    my $vgc = $configd->tree_get_full_hash("system boot-loader");
    $vgc = $vgc->{'boot-loader'};

    my $grub_users->{'user'} = $vgc->{'user'} if defined $vgc->{'user'};
    $grub_users = '' unless defined $grub_users;

    my $reduced = $vgc->{'reduced'};
    $reduced = 0 unless defined $reduced;

    my $index  = print_default_index();
    my @images = list_images();
    if ( $image ne "" ) {
        push( @images, $image );
    }

    my $pt_cmd = $pt_enable;
    my $iommu  = $configd->tree_get_full_hash("system iommu");
    if ( defined($iommu) ) {
        $iommu = $iommu->{'iommu'};

        my $passthrough = $iommu->{'passthrough'};
        $pt_cmd = $passthrough ? $pt_enable : "";
    }

    # Build a working grub.cfg with all images found...
    build_grub_cmd( $reduced, $index, $grub_users, $grub_cfg,
        $grub_template, $pt_cmd, @images );

    # Update onie
    if ( is_onie_system() ) {
        my $vcc = $configd->tree_get_full_hash("system console");
        $vcc = $vcc->{'console'};
        my $console = $vcc->{'serial-boot-console'};
        $console = "ttyS0" unless defined $console;
        my $console_speed = '';
        foreach my $i ( @{ $vcc->{'device'} } ) {
            if ( $i->{'tagnode'} eq $console ) {
                $console_speed = $i->{'speed'};
            }
        }

        # find the correct onie grub.cfg
        my $disk = `mount | grep '/boot/grub' | cut -d' ' -f1`;
        $disk = `basename $disk`;
        chomp($disk);
        $grub_onie_cfg = "/lib/live/mount/persistence/$disk/$grub_onie_cfg";
        build_onie_cmd( $console, $console_speed, $grub_users,
            $grub_onie_template, $grub_onie_cfg );
    }
}

sub toggle_reduced_cmd {
    my ( $option, $c ) = (@_);

    my $xcp = new XorpConfigParser();
    $xcp->parse($c);

    if ( $xcp->node_exists("system boot-loader reduced") ) {
        die __FILE__ . ": Grub reduced node alredy exists.\n";
    }

    $xcp->create_node( [ 'system', 'boot-loader', 'reduced' ] );
    $xcp->set_value( [ 'system', 'boot-loader', 'reduced' ], $option );

    my $CFGFILE;
    open $CFGFILE, ">$c";
    select $CFGFILE;
    $xcp->output(0);
}

my (
    $create_user, $build_grub,    $build_onie,     $list_images,
    $print_index, $generate_grub, $toggle_reduced, $set_index
);

GetOptions(
    "create-vy-grub-ubac=s"    => \$create_user,
    "create-vy-grub-reduced=s" => \$toggle_reduced,
    "build-grub:s"             => \$build_grub,
    "build-onie:s"             => \$build_onie,
    "list-images"              => \$list_images,
    "print-default-index"      => \$print_index,
    "set-default-boot-index=s" => \$set_index,
    "generate-grub:s"          => \$generate_grub
);

# EX: --create-vy-grub-ubac=vyatta,password,/config/config.boot
#     --create-vy-grub-ubac=vyatta,password
# This function adds grub user and password options to the vyatta config. Used
# to modify config.boot outside of configd. It sets the following nodes:
#   system boot-loader encrypted-passowrd
#   system boot-loader user
# Called by: install image
#
if ( defined($create_user) ) {
    if ( $create_user =~ /^(\w*),?(\w*),?([\w.\/0-9-_]*)$/ ) {
        my ( $user, $pass ) = ( $1, $2 );
        if ( $3 ne '' ) {
            $cfg_file = $3;
        }
        if ( $user eq '' ) {
            die __FILE__ . ": No grub username specified.\n";
        }
        if ( $pass eq '' ) {
            die __FILE__ . ": No grub password specified.\n";
        }
        if ( $cfg_file eq '' ) {
            $cfg_file = '/config/config.boot';
        }
        create_vyatta_config_grub_options( $user, $pass, $cfg_file );
        exit 0;
    }
    else {
        die __FILE__ . ": create-user: Input string malformed.\n";
    }
}

# EX: --toggle-reduced-grub=true/false
#
# This function lets you toggle the reduced grub menu option. It sets
# the following nodes:
#   system boot-loader reduced true/false
# Called by: install image
#
if ( defined($toggle_reduced) ) {
    if ( $toggle_reduced =~ /^(\w*),?([\w.\/0-9-_]*)$/ ) {
        my ($option) = ($1);
        if ( $2 ne '' ) {
            $cfg_file = $2;
        }
        if ( $option eq '' ) {
            die __FILE__ . ": No reduced toggle option specified.\n";
        }
        toggle_reduced_cmd( $option, $cfg_file );
        exit 0;
    }
    else {
        die __FILE__ . ": create-user: Input string malformed.\n";
    }
}

# EX: --build-grub=true,0,vyatta,password,/boot/grub/grub.cfg,"",image_name1,image_name2,...
#     --build-grub= [reduced grub layout:OPTIONAL],
#                   [default boot index:REQUIRED],
#                   [grub user:OPTIONAL],
#                   [grub pass:OPTIONAL],
#                   [default grub location:OPTIONAL],
#                   [default_template_location:OPTIONAL],
#                   [image_name:REQUIRED],...
#
# Builds a full or condensed grub.cfg. Grub and template parameters can be left blank for defaults
# or if not applicable.
# Called by: install image
#
if ( defined($build_grub) ) {
    if ( $build_grub =~
        /^(\w*),(\w*),(\w*),(\w*),([\w.\/0-9-_]*),([\w.\/0-9-_]*),(\S*)$/ )
    {
        my ( $reduced, $index, $grub_user, $grub_pass, $grub_cfg,
            $template_cfg, $images )
          = ( $1, $2, $3, $4, $5, $6, $7 );
        my @images = split /,/, $images;
        my $grub_users = '';
        if ( $grub_user ne '' && $grub_pass ne '' ) {
            my $gen_pass = gen_pass($grub_pass);
            $grub_users = {
                "user" => [
                    {
                        "user-id"            => $grub_user,
                        "encrypted-password" => $gen_pass,
                    }
                ]
            };
        }
        build_grub_cmd( $reduced, $index, $grub_users,
            $grub_cfg, $template_cfg, $pt_enable, @images );
        exit(0);
    }
    else {
        die __FILE__ . ": build-grub: Input string malformed.\n";
    }
}

# EX: --build-onie=ttyS0,1500,vyatta,password,/path/grub.cfg
#
# Build a grub-master onie config. Console and console speed should not be
# ommited. Leaving out inputs will attempt to get them from vconfig.
# Only called by install image.
#
if ( defined($build_onie) ) {
    my ( $console, $console_speed, $grub_user, $grub_pass );

    if ( $build_onie =~ /^(\w*),(\w*),(\w*),(\w*),([\w.\/0-9-_]*)$/ ) {
        ( $console, $console_speed, $grub_user, $grub_pass, $grub_onie_cfg ) =
          ( $1, $2, $3, $4, $5 );
    }
    else {
        die __FILE__ . ": build-onie: Input string malformed.\n";
    }

    my $grub_users = '';
    if ( $grub_user ne '' && $grub_pass ne '' ) {
        my $gen_pass = gen_pass($grub_pass);
        $grub_users = {
            "user" => [
                {
                    "user-id"            => $grub_user,
                    "encrypted-password" => $gen_pass,
                }
            ]
        };
    }

    build_onie_cmd( $console, $console_speed, $grub_users,
        $grub_onie_template, $grub_onie_cfg );
    exit(0);
}

# EX: --list-images
#
# Helper function: prints the names of all installed images in a special format
# Called by: Configd
#
if ( defined($list_images) ) {
    my @images = list_images();
    print join( ',', @images );
    exit(0);
}

# EX: --print-default-index
#
# Prints the index of the default boot image
# Called by: Configd
#
if ( defined($print_index) ) {
    print_default_index();
    exit(0);
}

# EX: --set-default-boot-index=18.3.0,/boot/grub/grub.cfg
#
# Wrapper for Live.pm function
# Called by: Installer
#
if ( defined($set_index) ) {
    if ( $set_index =~ /^(.*)$/ ) {
        my ($image) = ($1);
        if ( $image eq '' ) {
            die __FILE__ . ": No image name specified.\n";
        }
        set_default_boot_image($image);
        exit(0);
    }
    else {
        die __FILE__ . ": set-default-boot-index: Input string malformed.\n";
    }
}

# EX: --generate-grub
#
# Wrapper funciton to generate grub config from scratch. Takes an
# optional extra image name
#
if ( defined($generate_grub) ) {
    if ( $generate_grub =~ /^(\S*)/ ) {
        my ($image) = ($1);
        generate_grub_cmd($image);
    }
    else {
        generate_grub_cmd();
    }
    exit(0);
}

print "error: grub update cannot find an action.\n";
exit 1;
