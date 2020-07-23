#!/bin/bash

# disk helper functions
source disk_helper.sh

test_validate_partition_sizes ()
{
    _setup_lsblk

    mkdir ${SHUNIT_TMPDIR}/tmp
    touch  ${SHUNIT_TMPDIR}/tmp/install.log
    export INSTALL_LOG=/tmp/install.log

    # setup a 10.55GB Disk
    local size=10550000000
    _setup_partition sda KNAME=sda SIZE=$size # In bytes

    export INSTALL_DRIVE=sda
    export VII_DISK_LABEL=gpt
    export VII_BOOT_PART_SIZE=256
    export VII_ESP_PART_SIZE=512
    export VII_VYOS_PART_SIZE=4096
    export VII_VYOS_PART_MIN=4096
    export VII_VIRT_PART_SIZE=1024
    export VII_LOG_PART_SIZE=1024
    export VII_SWAP_PART_SIZE=1024
    export VII_ONIEBOOT_SIZE=0

    # Defaults pass?
    #output=$(validate_partition_sizes)
    #ret=$?
    #assertTrue "Default pass failed: $ret" $ret

    # Test where vrouter min size (<4096 for VR)
    # MIN REQ: vrouter + bios-boot + esp >= vii_vyos_part_minp
    #export VII_VYOS_PART_SIZE=3000
    #output=$(validate_partition_sizes)
    #ret=$?
    #assertFalse "Min vrouter pass failed: $ret" $ret

    # Test where partitions exceed drive space
    #export VII_LOG_PART_SIZE=7000
    #output=$(validate_partition_sizes)
    #ret=$?
    #assertFalse "Partitions too big pass failed: $ret" $ret

    # Test a bogus string input
    # We currently don't allow for inputs like "4GB", "4gigabyte",
    # "fourGiga", or "sgsdj#". Per documentation, please only input
    # whole 4000 (Megabyte) numbers.
    #export VII_VYOS_PART_SIZE=4GB
    #output=$(validate_partition_sizes)
    #ret=$?
    #assertFalse "String input pass failed: $ret" $ret

    # Test percentages
    #export VII_LOG_PART_SIZE='20%'
    #export VII_VIRT_PART_SIZE='10%'
    #output=$(validate_partition_sizes)
    #ret=$?
    #assertTrue "Percentages pass failed: $ret" $ret

    # Test failed percentages
    #export VII_LOG_PART_SIZE='200%'
    #export VII_VIRT_PART_SIZE='10%'
    #output=$(validate_partition_sizes)
    #ret=$?
    #assertFalse "Too high percentages pass failed: $ret" $ret

    rm -rf ${SHUNINT_TMPDIR}/dev
    unset -f lsblk

}

test_run_command ()
{
    TEXT=$(run_command echo 'Hello World' | awk '{ print $1 }')
    assertEquals 'Hello' "${TEXT}"

    echo 'Hello World' > ${SHUNIT_TMPDIR}/test.txt
    TEXT=$(run_command grep 'Hello World' ${SHUNIT_TMPDIR}/test.txt)
    assertEquals 'Hello World' "${TEXT}"

    TEXT=$(run_command grep 'Not Found' ${SHUNIT_TMPDIR}/test.txt 2>&1)
    assertEquals "ERROR: grep Not Found ${SHUNIT_TMPDIR}/test.txt" "${TEXT}"
}

test_run_command_stderr ()
{
    cat > ${SHUNIT_TMPDIR}/test.sh <<'EOF'
#!/bin/bash

set -x

func ()
{
    echo "VII_FUNCTION_TEST=olleh"
}

echo "VII_TEST_OUTPUT=hello"
func
EOF
    chmod +x ${SHUNIT_TMPDIR}/test.sh
    INSTALL_LOG="${SHUNIT_TMPDIR}/test.log"

    local TEXT=$(cd ${SHUNIT_TMPDIR} && run_command ./test.sh 2>&1)
    local EXPECTED="VII_TEST_OUTPUT=hello
VII_FUNCTION_TEST=olleh"
    assertEquals "${EXPECTED}" "${TEXT}"
    assertTrue "logfile exists" $(test -f "${SHUNIT_TMPDIR}/test.log" ; echo $?)
    EXPECTED="[test_run_command_stderr]:run_command: DEBUG: ./test.sh
[test_run_command_stderr]:run_command: + echo VII_TEST_OUTPUT=hello
+ func
+ echo VII_FUNCTION_TEST=olleh"
    assertEquals "${EXPECTED}" "$(cat ${SHUNIT_TMPDIR}/test.log)"
}

test_get_response_raw()
{
    local RESPONSE

    RESPONSE=$(get_response_raw "YAY" <<< "" )
    assertTrue "Unexpected return value" "$?"
    assertEquals "YAY" "${RESPONSE}"

    RESPONSE=$(get_response_raw "YAY" <<< "NEY" )
    assertTrue "Unexpected return value" "$?"
    assertEquals "NEY" "${RESPONSE}"

    RESPONSE=$(get_response_raw "YAY" "NEY YAY DONNO"<<< "NEY" )
    assertTrue "Unexpected return value" "$?"
    assertEquals "NEY" "${RESPONSE}"

    RESPONSE=$(get_response_raw "YAY" "NEY YAY DONNO"<<< "WHOO" )
    assertFalse "Unexpected return value" "$?"
    assertEquals "" "${RESPONSE}"
}

test_validate_image_name ()
{
    TEXT=$(validate_image_name "")
    assertFalse "Unexpected return value" $?

    TEXT=$(validate_image_name "vmlinuz")
    assertFalse "Unexpected return value" $?

    TEXT=$(validate_image_name "test/1")
    assertFalse "Unexpected return value" $?

    TEXT=$(validate_image_name "validimage")
    assertTrue "Unexpected return value" $?
}

test_install_image ()
{
    RESULT=$(install_image "${SHUNIT_TMPDIR}" "test0" "${SHUNIT_TMPDIR}")
    assertFalse "Unexpected return value" $?
    #echo ${RESULT} # cannot find squashfs

    RESULT=$(install_image "${SHUNIT_TMPDIR}" "test0" "${SHUNIT_TMPDIR}")
    assertFalse "Unexpected return value" $?
    #echo ${RESULT} # already installed

    mkdir -p ${SHUNIT_TMPDIR}/live
    echo "SQUASH" > ${SHUNIT_TMPDIR}/live/filesystem.squashfs
    mkdir -p ${SHUNIT_TMPDIR}/boot
    echo "VMLINUX" > ${SHUNIT_TMPDIR}/boot/vmlinux
    RESULT=$(install_image "${SHUNIT_TMPDIR}" "test1" "${SHUNIT_TMPDIR}")
    assertTrue "Unexpected return value" $?
    assertEquals "SQUASH" "$(cat ${SHUNIT_TMPDIR}/boot/test1/test1.squashfs)"
    assertEquals "VMLINUX" "$(cat ${SHUNIT_TMPDIR}/boot/test1/vmlinux)"

    RESULT=$(test -f ${SHUNIT_TMPDIR}/boot/test1/persistence/persistence.conf)
    assertTrue "No persistence.conf found" $?
}

test_get_vyatta_version ()
{
    assertEquals "UNKNOWN" \
		 "$(get_vyatta_version ${SHUNIT_TMPDIR} 2>/dev/null)"

    function try_mount ()
    {
	local DESTDIR=$(echo "${1##*filesystem.squashfs}" | tr -d '[:space:]')
	mkdir -p "${DESTDIR}/opt/vyatta/etc/"
	cat > "${DESTDIR}/opt/vyatta/etc/version" <<EOF
Version:      17.3.0-MASTER.01201911
Description:  Brocade vRouter 5600
Copyright:    2017 Brocade Communications Systems, Inc.
EOF
    }

    function umount ()
    {
	true
    }

    # first test without mounting
    rm -fr "${SHUNIT_TMPDIR}/live"
    mkdir -p "${SHUNIT_TMPDIR}/opt/vyatta/etc/"
    cat > "${SHUNIT_TMPDIR}/opt/vyatta/etc/version" <<EOF
Version:      999.master.02150325
Description:  Brocade vRouter 5600
Copyright:    2015 Brocade Communications Systems, Inc.
EOF
    assertEquals "999.master.02150325" \
		 "$(get_vyatta_version ${SHUNIT_TMPDIR} 2>/dev/null)"

    # second test with mounting
    mkdir -p "${SHUNIT_TMPDIR}/live"
    touch ${SHUNIT_TMPDIR}/live/filesystem.squashfs
    assertEquals "17.3.0-MASTER.01201911" \
		 "$(get_vyatta_version ${SHUNIT_TMPDIR} 2>/dev/null)"
}

get_live_persistence_label ()
{
    echo "persistence"
}

get_live_rootfs_path ()
{
    echo "${SHUNIT_TMPDIR}"
}

_create_filesystem_squashfs ()
{
    local DESTDIR=$1

    [ $# -ne 1 -o ! -d "${DESTDIR}" ] && return 1

    cat > ${DESTDIR}/filesystem.squashfs.uuencoded << 'EOF'
begin 644 filesystem.squashfs.gz
M'XL("%5?XU0"`W1E<W0N<W%U87-H9G,`[<VO2H-1',?AW]Y7P;'@Q&+48C&)
M9=%+\"_*&#A4F%56M+W"BH)%!G:+-V`T#(/,X)+))%B\"N<[/%Z!]7G*YWLX
M!\Y)][2;1<3NP>=.Q&1%5&(N!N6>*O=B_!JE/J>.DW8Z7Z?>ISZDKL39^]'A
M_M-P,!A^S(\;O<M*]IU7^M7^>>VVT[NZ>'O)5]?J>12=:K$P>=PN8KGQ.MJX
M:;;N]K8VLYCMYLU:>;/=7I^.K!Y+?W_,%%]YQ'&Y'@,`````````````````
M````````````````````````````````````````````````````````````
0`````(#_^0'KFF'(```!````
`
end
EOF

    uudecode -o ${DESTDIR}/filesystem.squashfs.gz \
	${DESTDIR}/filesystem.squashfs.uuencoded
    rm -f ${DESTDIR}/filesystem.squashfs.uuencoded
    gunzip -f ${DESTDIR}/filesystem.squashfs.gz
}

test_check_install_source ()
{
    mkdir -p "${SHUNIT_TMPDIR}"/live/

    TEXT=$(check_install_source ${SHUNIT_TMPDIR})
    assertFalse "Unexpected return value: $?" $?
    assertTrue "Unexpected error message: \"${TEXT}\"" \
	"echo ${TEXT} | grep -q 'Vyatta ISO image'"

    _create_filesystem_squashfs ${SHUNIT_TMPDIR}/live
    echo 'ii  vyatta-version ' > "${SHUNIT_TMPDIR}"/live/packages.txt

    TEXT=$(check_install_source ${SHUNIT_TMPDIR})
    assertFalse "Unexpected return value: $?" $?
    assertTrue "Unexpected error message: \"${TEXT}\"" \
	"echo ${TEXT} | grep -q 'MD5 checksum file'"

    cat > ${SHUNIT_TMPDIR}/md5sum.txt << 'EOF'
00000000000000000000000000000000  live/filesystem.squashfs
EOF
    TEXT=$(check_install_source ${SHUNIT_TMPDIR})
    assertFalse "Unexpected return value: $?" $?
    assertTrue "Unexpected error message: \"${TEXT}\"" \
	"echo ${TEXT} | grep -q '...Failed'"

    cat > ${SHUNIT_TMPDIR}/md5sum.txt << 'EOF'
acc6e4c5b58cf3dcccb0aed157663775  live/filesystem.squashfs
EOF
    TEXT=$(check_install_source ${SHUNIT_TMPDIR})
    assertTrue "Unexpected return value: $?" $?
    assertTrue "Unexpected error message: \"${TEXT}\"" \
	"echo ${TEXT} | grep -q '...OK'"
}

test_mktempdir ()
{
    assertFalse "Directory doesn't exist" \
	"[ -d ${SHUNIT_TMPDIR}/$(basename $0)*/medium ]"

    TEXT=$(mktempdir)
    assertTrue "Unexpected return value: $?" $?
    assertTrue "Return value is a directory" "[ -d \"${TEXT}\" ]"
    assertTrue "Directory exists in correct path" \
	"[ -d ${SHUNIT_TMPDIR}/$(basename $0)* ]"

    TEXT=$(mktempdir medium)
    assertTrue "Return value is non-zero" "[ -n \"${TEXT}\" ]"
    assertTrue "Return value is a directory" "[ -d \"${TEXT}\" ]"
    assertTrue "Directory exists" \
	"[ -d ${SHUNIT_TMPDIR}/$(basename $0)*/medium ]"

    TEXT=$(mktempdir rootfs)
    assertTrue "Directories are siblings" "[ -d ${TEXT}/../medium ]"
}

test__check_iso_signature ()
{
    # Initial setup required by gpg2
    mkdir -p ${SHUNIT_TMPDIR}/.gnupg
    chmod 0700 ${SHUNIT_TMPDIR}/.gnupg
    export GNUPGHOME=${SHUNIT_TMPDIR}/.gnupg
    gpg --import-ownertrust 2>/dev/null <<EOF
# List of assigned trustvalues, created Thu 19 Feb 2015 01:50:34 PM CET
# (Use "gpg --import-ownertrust" to restore them)
3944B4E94F69D1B0E907FAA80ECB422D7C864745:6:
EOF
    gpg --import 2>/dev/null <<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0.22 (GNU/Linux)

mQENBFLYXlIBCADIRruDZ+LZf5aPfibFdqYL6uyAyhSgwK+ZhekGnNqqC+s0mUPU
ri71g3WrkIhZBhcuvo+oKuCqd8OhZ7n8jK3bozJ2dOLwZSwu74BczbqCZS2f/fTN
NrPXpjr2TlWKDGtwm3ebhlRw98NZxlDypzglaVyItieKLAxKwHE/7Rp+y2gamWTY
1XRztQVvktX8Nk/aY8IWdBIYPstq72loI26mVlih/BrZj5i0tFNqd99b4GHlsu07
R40XzDNB0/R5svJXOFobIlKvWajGop1VH0/YdpSaQRn7VQPLiqs7WN6Rr54uQ1nf
3x04KBSJ1YqxqHuVfDI/zIBQ69nq2drssy1jABEBAAG0I0phbiBCbHVuY2sgPGph
bi5ibHVuY2tAYnJvY2FkZS5jb20+iQE/BBMBAgApBQJS2F5SAhsjBQkJZgGABwsJ
CAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQDstCLXyGR0VADQf8DLCG8pPydMjm
IvjZ/w2IbaU4x5WbBi7gS6mpRJJDiGJHhC2b2dg1cl3JqRynuZn6Y4Cxm277oJvm
WXJJWo4NVs0tvjFh1Pq9JFQYN5DJZXzDUEAVYjNiVCOXUMu5hojd+eg5/foQQhfd
/cA3DOiiDFFUjZgJ1FxW04WncaG71XVA3ml6sZlpjdj5P+iYQLPkZ6WmePtNDhPr
fjDrmr2TF+U9O9VIAyQQziQLhgkCHA52+/4t3AHXvlAxztSFyUILdHaDic0Zc3dN
/G+hgPrh0nQfJDRvKAxOXNMunHbFpJmwsnw+pbK//MbROfO4qL19NE2opqGqVjLR
bytND/03Y7kBDQRS2F5SAQgAvS4446PHiIkJ2RIzT/xc7sqn/E3H36jJTm70cHPb
dq2Ny/YTFLUslaJI5ngKhzC5WCSIlFhYH0Zb2Laoyfa3OBR7vXSsv2DkRK2Zb5BF
VmM7pH1y3PReIVQOuPvI+hu/b+DGg1lXbhJYZ7RYKFVQOveOyyWllKniDRUZXmjK
K5uZGLpZ6rstFhw3H1/tVMnRWw+uInv+XLkDFLyzRUFuWln7BOxChaMj7zysIf2C
0cK2kijvFdWiEPD6X6CSGUZLbQtaNNT5R6KzqFjBVJ8pNYYO1XuWeO9BDJUX4WWn
H1kG1fPbqYYdQNtHEvpdCkjUeRKwES45C84/5o0r1SI9YQARAQABiQElBBgBAgAP
BQJS2F5SAhsMBQkJZgGAAAoJEA7LQi18hkdFc7sIALde+Ubi9L73HIv1di6/Ch6v
3ocbsReIxi3lWlSNgxF+LviAzFDu2vtAsfEvKnTFMzjXkIAcm7uY/FeRoUWzYuzR
4C6O/lHgWZntUXo2vA/2aaca9U/Iww0ddsuTfP2SvV+bh/HTRmzfyCZDmnni4Cyg
oDOvsiJmtk8Hyn0if2dKEwnEqF9qJBfbcwIZHt+mKLz0Z1qgWYmH/LseklXyxwoS
PCGXZQquCEdngE+PP7lREcYWkHas5UcYsDG5KEeF5mtSwk7r3dn9K0i71hA4Fy+o
9D/721X/32PGgTudTYM0LoT6QsdBodYQi5UbXYC3mqUuMGPiEtNKTFlREC6/I3c=
=w16n
-----END PGP PUBLIC KEY BLOCK-----
EOF

    # save stdin in fd 3 to be able to restore it later
    exec 3<&0
    # automatically hit return when prompted
    exec < <( yes "" )

    TEXT=$(_check_iso_signature 2>&1)
    assertFalse "Unexpected return value: $?" $?
    assertTrue "Error includues 'Required parameter': ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Required parameter' ; echo $?)

    TEXT=$(_check_iso_signature ${SHUNIT_TMPDIR}/hello.txt.asc \
	${SHUNIT_TMPDIR}/.gnupg/trustdb.gpg 2>&1)
    assertFalse "Unexpected return value: $?" $?
    assertTrue "fail_exit is called: ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Exiting' ; echo $?)

    echo "Hello World" > ${SHUNIT_TMPDIR}/hello.txt
    echo > ${SHUNIT_TMPDIR}/hello.txt.asc

    TEXT=$(_check_iso_signature ${SHUNIT_TMPDIR}/hello.txt.asc \
	${SHUNIT_TMPDIR}/.gnupg/trustdb.gpg 2>&1)
    assertFalse "Unexpected return value: $?" $?
    assertTrue "fail_exit is called: ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Exiting' ; echo $?)

    cat > ${SHUNIT_TMPDIR}/hello.txt.asc <<EOF
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2.0.22 (GNU/Linux)

iQEcBAABAgAGBQJU5dvDAAoJEA7LQi18hkdFw4AIALzHLcuOZUnasf+xaOUCYC56
ZrX44CfnjNfIXLNlakDRUM130PyyfOrO2bhpUXv6pmxo5lJjoSzlhm1GBc8DXh8w
4WI+VdEI81zLgiKZ5AnptgaT1sbQJTqrzuNqJidFgp3I3wZkX8+NS0u6w4CJrJjU
DQsPvfo3+MA5aXS3wKMaAeCXtpuKIHEfvfPtGHlbXamWVaDx7/eaV0IEZ5xixmLS
84c6+uXXtkl7QxBTfi7JBSgie5tM6KY62ZnGsak9IdLEZxn4mFyRZXDR488zEUt8
mD3JIUGFPtSAexvil1QYD7Urr8J2RYy3tv1a0nL5v3BcclbcEWWo3utfwqyQnXg=
=OZ+P
-----END PGP SIGNATURE-----
EOF

    # test with invalid keyring
    TEXT=$(_check_iso_signature ${SHUNIT_TMPDIR}/hello.txt.asc 2>&1)
    assertFalse "Unexpected return value: $?" $?
    assertTrue "fail_exit is called: ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Exiting' ; echo $?)

    TEXT=$(_check_iso_signature ${SHUNIT_TMPDIR}/hello.txt.asc \
	${SHUNIT_TMPDIR}/.gnupg/trustdb.gpg 2>&1)
    assertTrue "Unexpected return value: $?" $?
    assertTrue "Error include 'Valid': ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Valid' ; echo $?)
    assertFalse "fail_exit is called: ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Exiting' ; echo $?)

    # detect corrupt signature
    echo "!" >> ${SHUNIT_TMPDIR}/hello.txt
    TEXT=$(_check_iso_signature ${SHUNIT_TMPDIR}/hello.txt.asc \
	${SHUNIT_TMPDIR}/.gnupg/trustdb.gpg 2>&1)
    assertFalse "Unexpected return value: $?" $?
    assertTrue "fail_exit is called: ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Exiting' ; echo $?)

    # detect corrupt signature but proceed anyway
    # automatically hit 'y' return when prompted
    exec < <( yes "y" )
    TEXT=$(_check_iso_signature ${SHUNIT_TMPDIR}/hello.txt.asc \
	${SHUNIT_TMPDIR}/.gnupg/trustdb.gpg 2>&1)
    assertTrue "Unexpected return value: $?" $?
    assertTrue "Error include 'Proceeding': ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Proceeding' ; echo $?)
    assertFalse "fail_exit is called: ${TEXT}" \
	$(echo ${TEXT} | grep -q 'Exiting' ; echo $?)

    # restore stdin from fd 3
    exec 0<&3 3<&-
}

test_parse_vii_config ()
{
    local CONFIG_DIR=${SHUNIT_TMPDIR}/parse_vii_config
    mkdir -p ${CONFIG_DIR}

    OLD_IFS=${IFS} ; IFS=$'\n'
    TEXT=(
	$(IFS=${OLD_IFS} echo VII_NAME=test | parse_vii_config - 2>&1 ; \
	    echo "RETURN=$?" ; echo "VII_NAME=${VII_NAME:-Unknown}")
    )
    IFS=${OLD_IFS}

    assertTrue "Unexpected error string: ${TEXT[0]}" \
	$(echo ${TEXT[0]} | grep -q 'No such file' ; echo $?)
    assertEquals "Unexpected return value" \
	"RETURN=1" "${TEXT[1]}"
    assertEquals "Environment variable unset" "VII_NAME=Unknown" \
	"${TEXT[2]}"

    OLD_IFS=${IFS} ; IFS=$'\n'
    TEXT=(
	$(IFS=${OLD_IFS} parse_vii_config ${CONFIG_DIR}/invalid.config 2>&1 ; \
	    echo "RETURN=$?" ; echo "VII_NAME=${VII_NAME:-Unknown}")
    )
    IFS=${OLD_IFS}

    assertTrue "Unexpected error string: ${TEXT[0]}" \
	$(echo ${TEXT[0]} | grep -q 'No such file' ; echo $?)
    assertEquals "Unexpected return value" \
	"RETURN=1" "${TEXT[1]}"
    assertEquals "Environment variable unset" "VII_NAME=Unknown" \
	"${TEXT[2]}"

    cat > ${CONFIG_DIR}/invalid.config <<EOF
# This is a comment
VII_NAME=test
cat /etc/shadow-
EOF
    OLD_IFS=${IFS} ; IFS=$'\n'
    TEXT=(
	$(IFS=${OLD_IFS} parse_vii_config ${CONFIG_DIR}/invalid.config 2>&1 ; \
	    echo "RETURN=$?" ; echo "VII_NAME=${VII_NAME:-Unknown}")
    )
    IFS=${OLD_IFS}

    assertTrue "Unexpected error string: ${TEXT[0]}" \
	"$(echo ${TEXT[0]} | grep -q 'config file is unclean' ; echo $?)"
    assertEquals "Unexpected return value" \
	"RETURN=1" "${TEXT[1]}"
    assertEquals "Environment variable unset" "VII_NAME=Unknown" \
	"${TEXT[2]}"

    cat > ${CONFIG_DIR}/valid.config <<EOF
# This is a comment
VII_IMAGE_NAME=test
VII_ADMIN_USERNAME=vyatta
VII_ADMIN_PASSWORD=$1$05FAjo9W$D3m1zEOKd12kOKYF.pVPc\/

EOF

    OLD_IFS=${IFS} ; IFS=$'\n'
    TEXT=(
	$(IFS=${OLD_IFS} parse_vii_config ${CONFIG_DIR}/valid.config 2>&1 ; \
	    echo "RETURN=$?" ; echo "VII_NAME=${VII_IMAGE_NAME:-Unknown}")
    )
    IFS=${OLD_IFS}

    assertEquals "Unexpected number of return lines" \
	"2" "${#TEXT[*]}"
    assertEquals "Unexpected return value" \
	"RETURN=0" "${TEXT[0]}"
    assertEquals "Environment variable unset" "VII_NAME=test" \
	"${TEXT[1]}"
}

test_create_admin_account ()
{
    mkdir -p ${SHUNIT_TMPDIR}/etc
    mkdir -p ${SHUNIT_TMPDIR}/sbin
    ln -fs "$(which true)" ${SHUNIT_TMPDIR}/sbin/vyatta_check_username.pl || \
	fail "Unable to mock vyatta_check_username.pl"
    cat > ${SHUNIT_TMPDIR}/sbin/vyatta_create_account <<EOF
#!/bin/sh
echo ARGS=\"\$@\" >&2
EOF
    chmod +x ${SHUNIT_TMPDIR}/sbin/vyatta_create_account
    declare vyatta_sbindir=${SHUNIT_TMPDIR}/sbin

    mkdir -p ${SHUNIT_TMPDIR}/config
    cat > ${SHUNIT_TMPDIR}/config/config.boot <<EOF
system {
        login {
                user vyatta {
                        authentication {
                                encrypted-password 12345678
                        }
                }
        }
}
EOF

    VII_ADMIN_USERNAME="myadmin"
    VII_ADMIN_PASSWORD="12345678"
    TEXT=$(create_admin_account ${SHUNIT_TMPDIR}/config/config.boot \
        ${SHUNIT_TMPDIR} 2>&1)
    assertTrue "Default account is used: ${TEXT}" \
	$(echo ${TEXT} | grep -q '[myadmin]' ; echo $?)
    assertTrue "vyatta_create_account called with --admin=myadmin" \
	$(echo ${TEXT} | grep -q '\--admin=myadmin' ; echo $?)
    assertTrue "config.boot doesn't update encrypted password of vyatta user" \
	$(grep -q 'encrypted-password 12345678' \
	${SHUNIT_TMPDIR}/config/config.boot ; echo $?)
}

test_fetch_by_url ()
{
    TEXT=$(fetch_by_url /${SHUNIT_TMPDIR}/config/config.boot)
    assertTrue "Returns successful" $?
    assertEquals "/${SHUNIT_TMPDIR}/config/config.boot" "${TEXT}"

    TEXT=$(fetch_by_url file:/${SHUNIT_TMPDIR}/config/config.boot)
    assertTrue "Returns successful" $?
    assertEquals "/${SHUNIT_TMPDIR}/config/config.boot" "${TEXT}"

    function curl ()
    {
	echo "ARGS=$*"
    }

    OLD_IFS=${IFS} ; IFS=$'\n'
    TEXT=(
	$(IFS=${OLD_IFS} fetch_by_url http://www.google.com/robots.txt 2>&1 ; \
	    echo "RETURN=$?")
    )
    IFS=${OLD_IFS}
    assertEquals "3" "${#TEXT[@]}"
    assertTrue "${TEXT[0]}" \
	$(echo ${TEXT[0]} | grep -q '\-o robots.txt' ; echo $?)
    assertEquals "robots.txt" "${TEXT[1]}"
    assertEquals "RETURN=0" "${TEXT[2]}"

    OLD_IFS=${IFS} ; IFS=$'\n'
    TEXT=(
	$(IFS=${OLD_IFS} fetch_by_url http://www.google.com/robots.txt \
	    out.txt 2>&1 ; echo "RETURN=$?")
    )
    IFS=${OLD_IFS}
    assertEquals "3" "${#TEXT[@]}"
    assertTrue "${TEXT[0]}" \
	$(echo ${TEXT[0]} | grep -q '\-o out.txt' ; echo $?)
    assertEquals "out.txt" "${TEXT[1]}"
    assertEquals "RETURN=0" "${TEXT[2]}"

    # a failing curl test
    function curl ()
    {
	echo "ARGS=$*"
	false
    }

    OLD_IFS=${IFS} ; IFS=$'\n'
    TEXT=(
	$(IFS=${OLD_IFS} fetch_by_url http://www.google.com/robots.txt 2>&1 ; \
	    echo "RETURN=$?")
    )
    IFS=${OLD_IFS}
    assertEquals "4" "${#TEXT[@]}"
    assertTrue "${TEXT[0]}" \
	$(echo ${TEXT[0]} | grep -q '\-o robots.txt' ; echo $?)
    assertEquals "RETURN=1" "${TEXT[3]}"

    # an unsupported URL
    OLD_IFS=${IFS} ; IFS=$'\n'
    TEXT=(
	$(IFS=${OLD_IFS} fetch_by_url oink://www.google.com/robots.txt 2>&1 ; \
	    echo "RETURN=$?")
    )
    IFS=${OLD_IFS}
    assertEquals "2" "${#TEXT[@]}"
    assertTrue "${TEXT[0]}" \
	$(echo ${TEXT[0]} | grep -q 'Unsupported URL' ; echo $?)
    assertEquals "RETURN=1" "${TEXT[1]}"
}

test_copy_config ()
{
    function set_encrypted_password ()
    {
	true
    }

    function create_admin_account ()
    {
	true
    }

    function create_admin_grub_account ()
    {
	true
    }

    function fetch_by_url ()
    {
	echo "interfaces { } system { }" > "$2"
	echo "$2"
    }

    # Instead of writing a full emulation of install, handle
    # copy_config()'s call to install with the fourth argument
    # as the config directory it wants to create
    function install ()
    {
	mkdir "$4"
    }

    function chgrp ()
    {
	true
    }

    local cfg_dir="${SHUNIT_TMPDIR}${VYATTA_NEW_CFG_DIR}"
    __vyatta_sysconfdir="${vyatta_sysconfdir}"
    export vyatta_sysconfdir="${SHUNIT_TMPDIR}/opt/vyatta/etc"
    mkdir -p "${vyatta_sysconfdir}/config"
    touch "${vyatta_sysconfdir}/config.boot.default"

    # auto install from file
    rm -rf "${cfg_dir}"
    echo "interfaces { } system { }" > "${SHUNIT_TMPDIR}/vii.config.boot"
    export VII_IMAGE_CONFIG_BOOT="${SHUNIT_TMPDIR}/vii.config.boot"
    RESPONSE=$(copy_config /${SHUNIT_TMPDIR} < /dev/null)
    assertTrue "Unexpected return value" "$?"
    assertTrue "Marker exists in /config" \
	"[ -f ${cfg_dir}/.vyatta_config ]"
    assertTrue "config.boot exists in /config" \
	"[ -f ${cfg_dir}/config.boot ]"

    # auto install from URL
    rm -rf "${cfg_dir}"
    export VII_IMAGE_CONFIG_BOOT="http://www.google.com/robots.txt"
    RESPONSE=$(copy_config /${SHUNIT_TMPDIR} < /dev/null)
    assertTrue "Unexpected return value" "$?"
    assertTrue "Marker exists in /config" \
	"[ -f ${cfg_dir}/.vyatta_config ]"
    assertTrue "config.boot exists in /config" \
	"[ -f ${cfg_dir}/config.boot ]"

    # failed auto install from file
    rm -rf "${cfg_dir}"
    export VII_IMAGE_CONFIG_BOOT="/this-file-does-not-exist"
    RESPONSE=$(copy_config /${SHUNIT_TMPDIR} < /dev/null 2>/dev/null)
    assertFalse "Unexpected return value" "$?"
    assertTrue "Marker exists in /config" \
	"[ -f ${cfg_dir}/.vyatta_config ]"
    assertFalse "config.boot exists in /config" \
	"[ -f ${cfg_dir}/config.boot ]"

    vyatta_sysconfdir="${__vyatta_sysconfdir}"

    unset -f install
}

test_detect_loop_backing_device ()
{
    local RESPONSE

    local DEVICE_NAME_BAD="/dev/loop1"
    # not existing loop device entry
    RESPONSE=$(detect_loop_backing_device ${DEVICE_NAME_BAD})
    assertEquals "" "${RESPONSE}"

    # not existing backing_file sysfs entry
    mkdir -p ${SHUNIT_TMPDIR}/sys/block/${DEVICE_NAME_BAD##*/}/loop/
    RESPONSE=$(detect_loop_backing_device ${DEVICE_NAME_BAD})
    assertEquals "" "${RESPONSE}"

    # empty backing_file sysfs entry
    echo -n "" > ${SHUNIT_TMPDIR}/sys/block/${DEVICE_NAME_BAD##*/}/loop/backing_file
    RESPONSE=$(detect_loop_backing_device ${DEVICE_NAME_BAD})
    assertEquals "" "${RESPONSE}"

    # Invalid stat output
    function stat ()
    {
         echo -n ""
    }
    RESPONSE=$(detect_loop_backing_device ${DEVICE_NAME_BAD})
    assertEquals "" "${RESPONSE}"


    # All good.
    DEVICE_NAME_GOOD="/dev/loop0"
    SYSFS_LOOPDEVICE_GOOD="${SHUNIT_TMPDIR}/sys/block/${DEVICE_NAME_GOOD##*/}/loop/"
    mkdir -p ${SYSFS_LOOPDEVICE_GOOD}
    BACKING_FILE_GOOD="${SYSFS_LOOPDEVICE_GOOD}/backing_file"
    echo "/lib/live/mount/media/live/filesystem.squashfs" > ${BACKING_FILE_GOOD}

    function stat ()
    {
         echo -n "fe01"
    }

    RESPONSE=$(detect_loop_backing_device ${DEVICE_NAME_GOOD})
    assertEquals "fe:01" ${RESPONSE}
}

test_run_pre_install_hooks ()
{
    local RESPONSE

    declare vyatta_datadir=${SHUNIT_TMPDIR}/opt/vyatta/share

    mkdir -p ${SHUNIT_TMPDIR}/cdroot
    mkdir -p ${vyatta_datadir}/preinstall.d
cat > ${vyatta_datadir}/preinstall.d/10-unittest<<EOF
#!/bin/bash

set -e

case "\$1" in
    configure)
        echo "VII_PREINSTALL_UNITTEST=\${VII_PREINSTALL_UNITTEST:-true}"
        ;;
    run)
        [ "\${VII_PREINSTALL_UNITTEST}" = "true" ] && echo "unit test" > \$2/unittest
        ;;
    *)
	echo "unknown command: \"\$1\""
	exit 1
        ;;
esac

exit 0
EOF
    chmod 755 ${vyatta_datadir}/preinstall.d/10-unittest

    # run 10-unitest
    RESPONSE=$(run_pre_install_hooks ${SHUNIT_TMPDIR}/cdroot)
    assertEquals "" "${RESPONSE}"
    assertEquals "unit test" "$(cat ${SHUNIT_TMPDIR}/cdroot/unittest)"

    # fail if missing arguments
    RESPONSE=$(run_pre_install_hooks)
    assertFalse "Returns false" $?
}


test_run_post_install_hooks ()
{
    vyatta_datadir="${SHUNIT_TMPDIR}/opt/vyatta/share"
    export vyatta_datadir

    mkdir -p "${vyatta_datadir}/postinstall.d"
    cat > "${vyatta_datadir}/postinstall.d/00-test" <<'EOF'
#!/bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

case "$1" in
    configure)
	echo "VII_00_TEST=bar"
	;;
    run)
	env > ${DIR}/00-test.log
	;;
    *)
	fail_exit "$0: unknown command: \"$1\""
	;;
esac

exit 0
EOF
    chmod +x "${vyatta_datadir}/postinstall.d/00-test"

    OINK_UNITTEST_GLOBAL="oink"
    OINK_UNITTEST_EXPORT="oink"
    export OINK_UNITTEST_EXPORT

    run_post_install_hooks "${SHUNIT_TMPDIR}" oink

    assertTrue "logfile created" $(test -f "${vyatta_datadir}/postinstall.d/00-test.log" ; echo $?)
    assertTrue "VII_00_TEST exists" $(grep -qE '^VII_00_TEST=' "${vyatta_datadir}/postinstall.d/00-test.log" ; echo $?)
    assertTrue "VII_CONSOLE exists" $(grep -qE '^VII_CONSOLE=' "${vyatta_datadir}/postinstall.d/00-test.log" ; echo $?)
    assertTrue "OINK_UNITTEST_EXPORT exists" $(grep -qE '^OINK_UNITTEST_EXPORT=' "${vyatta_datadir}/postinstall.d/00-test.log" ; echo $?)
    assertFalse "OINK_UNITTEST_GLOBAL doesn't exist" $(grep -qE '^OINK_UNITTEST_GLOBAL=' "${vyatta_datadir}/postinstall.d/00-test.log" ; echo $?)
}

test_detect_console ()
{
    local RESPONSE
    export vyatta_origin_tty

    vyatta_origin_tty=""
    RESPONSE=$(detect_console)
    assertEquals "tty0" "${RESPONSE}"

    vyatta_origin_tty="/dev/tty1"
    RESPONSE=$(detect_console)
    assertEquals "tty0" "${RESPONSE}"

    vyatta_origin_tty="/dev/ttyS0"
    RESPONSE=$(detect_console)
    assertEquals "ttyS0" "${RESPONSE}"

    vyatta_origin_tty="/dev/pts/8"
    RESPONSE=$(detect_console)
    assertEquals "tty0" "${RESPONSE}"

    mkdir -p "${SHUNIT_TMPDIR}/sys/class/tty/console"
    echo "tty0 ttyS0" > "${SHUNIT_TMPDIR}/sys/class/tty/console/active"
    vyatta_origin_tty="/dev/pts/8"
    RESPONSE=$(detect_console)
    assertEquals "ttyS0" "${RESPONSE}"

    # repeat the test for vyatta_origin_tty which should return the active
    # console this time instead of the fallback value
    vyatta_origin_tty=""
    RESPONSE=$(detect_console)
    assertEquals "ttyS0" "${RESPONSE}"

    vyatta_origin_tty="/dev/console"
    RESPONSE=$(detect_console)
    assertEquals "ttyS0" "${RESPONSE}"
}

oneTimeSetUp ()
{
    local THIS_DIR=$(cd $(dirname ${0}); pwd -P)

    # make SUT visible
    PATH="${THIS_DIR}/../scripts/:${PATH}"
    export PATH

    # the implementation knows about unittest implementation
    if [ -z "${SHUNIT_TMPDIR}" ] ; then
	SHUNIT_TMPDIR=`mktemp -d`
	trap "rm -rf ${SHUNIT_TMPDIR}" EXIT
    fi
    export SHUNIT_TMPDIR

    export INSTALL_LOG=""

    TMPDIR=${SHUNIT_TMPDIR}
    export TMPDIR

    . ${THIS_DIR}/../scripts/vyatta-install-image.functions
    . ${THIS_DIR}/../scripts/vyatta-create-partition.functions
    . ${THIS_DIR}/../vii_database/vii.defaults
}

tearDown ()
{
    # clean-up after every test
    if [ -n "${SHUNIT_TMPDIR}" ] ; then
	rm -fr "${SHUNIT_TMPDIR}/*"
    fi
}


# load and run shUnit2
[ -n "${ZSH_VERSION:-}" ] && SHUNIT_PARENT=$0
. shunit2
