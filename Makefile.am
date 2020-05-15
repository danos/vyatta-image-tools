SUBDIRS = . doc tests

opdir = $(datadir)/vyatta-op/templates
techsprtdir = $(datadir)/vyatta-op/functions/tech-support.d
share_perl5dir = /opt/vyatta/share/perl5/Vyatta
etcgrubdir = /opt/vyatta/etc/grub
viidir = /opt/vyatta/etc/install-image/

bin_SCRIPTS =
sbin_SCRIPTS =
sysconf_DATA =
share_perl5_DATA = lib/Vyatta/Live.pm
etcgrub_DATA = etc/grub/default-union-grub-entry
etcgrub_DATA += etc/grub/default-union-grub.template
etcgrub_DATA += etc/grub/grub-onie.template
vii_DATA = vii_database/vii.defaults

sbin_SCRIPTS += scripts/vyatta-live-image
sbin_SCRIPTS += scripts/vyatta-live-image.functions
sbin_SCRIPTS += scripts/vyatta-image-tools.pl
sbin_SCRIPTS += scripts/install-get-partition
sbin_SCRIPTS += scripts/install-get-partition.functions
sbin_SCRIPTS += scripts/vyatta-install-image
sbin_SCRIPTS += scripts/vyatta-install-image.functions
sbin_SCRIPTS += scripts/vyatta-image-migrate-lb4
sbin_SCRIPTS += scripts/vyatta-postinstall-configure
sbin_SCRIPTS += scripts/vyatta-postinstall-setup-console
sbin_SCRIPTS += scripts/vyatta-create-partition
sbin_SCRIPTS += scripts/vyatta-create-partition.functions
sbin_SCRIPTS += scripts/vyatta-multiple-partition
sbin_SCRIPTS += scripts/vyatta-multiple-partition.functions
sbin_SCRIPTS += scripts/vyatta_update_grub.pl
sbin_SCRIPTS += scripts/vyatta-hotfix
sbin_SCRIPTS += scripts/vyatta-squashfs-chroot

postinstallddir = $(datadir)/postinstall.d
postinstalld_SCRIPTS = postinstall.d/50-example
postinstalld_SCRIPTS += postinstall.d/50-vyatta-misc
postinstalld_SCRIPTS += postinstall.d/55-update-grub
postinstalld_SCRIPTS += postinstall.d/55-update-signed-efi
postinstalld_SCRIPTS += postinstall.d/70-vyatta-xen
postinstalld_SCRIPTS += postinstall.d/80-create-raid-config
postinstalld_SCRIPTS += postinstall.d/90-configure
postinstalld_SCRIPTS += postinstall.d/93-machine-id
postinstalld_SCRIPTS += postinstall.d/95-mount-var-log
postinstalld_SCRIPTS += postinstall.d/96-copy-var-log-to-partition
postinstalld_SCRIPTS += postinstall.d/97-vyatta-install-log
postinstalld_SCRIPTS += postinstall.d/98-umount-var-log

preinstallddir = $(datadir)/preinstall.d
preinstalld_SCRIPTS = preinstall.d/10-virtualization
preinstalld_SCRIPTS = preinstall.d/50-example

postinstallcompatdir = $(prefix)/etc/install-image
postinstallcompat_SCRIPTS = etc/install-system/postinst

systemddir = /lib/systemd

AM_CFLAGS = -I /usr/include/vyatta-cfg

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)
	mkdir -p $(DESTDIR)$(systemddir)
	cd systemd ; $(cpiop) $(DESTDIR)$(systemddir)
	mkdir -p $(DESTDIR)$(techsprtdir)
	cd share/vyatta-op/functions/tech-support.d ; $(cpiop) $(DESTDIR)$(techsprtdir)
