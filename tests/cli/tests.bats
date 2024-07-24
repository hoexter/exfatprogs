setup() {
    load '/usr/lib/bats/bats-assert/load.bash'
    bats_require_minimum_version 1.7.0
}

setup_file() {
    # get the containing directory of this file
    # use $BATS_TEST_FILENAME instead of ${BASH_SOURCE[0]} or $0,
    # as those will point to the bats executable's location or the preprocessed file respectively
    DIR="$( cd "$( dirname "$BATS_TEST_FILENAME" )" >/dev/null 2>&1 && pwd )"
    LOOP_DEV="/dev/loop22"
    export EXFAT_PROGS_VER="$(grep EXFAT_PROGS_VERSION ${DIR}/../../include/version.h | cut -d'"' -f 2)"
    export DUMP_CMD="sudo ${DIR}/../../dump/dump.exfat"
    export FSCK_CMD="sudo ${DIR}/../../fsck/fsck.exfat"
    export IMG_CMD="sudo ${DIR}/../../exfat2img/exfat2img"
    export LABEL_CMD="sudo ${DIR}/../../label/exfatlabel"
    export MKFS_CMD="sudo ${DIR}/../../mkfs/mkfs.exfat"
    export TUNE_CMD="sudo ${DIR}/../../tune/tune.exfat"

    truncate -s 100M test.img
    sudo mkdir -p /mnt/test
    sudo losetup ${LOOP_DEV} test.img
    sudo mkfs.exfat ${LOOP_DEV}
}

teardown_file() {
    sudo losetup -d ${LOOP_DEV}
    sudo rmdir /mnt/test
    rm test.img
}

@test "exfatlabel get mkfs set volume serial" {
    run -0 ${LABEL_CMD} -i ${LOOP_DEV}
    assert_output -e "volume serial : 0x[0-9a-f]+"
}

@test "exfatlabel set volume serial 1" {
    run -0 ${LABEL_CMD} -i ${LOOP_DEV} 0xc0ffee1
}

@test "exfatlabel get new volume serial 1" {
    run -0 ${LABEL_CMD} -i ${LOOP_DEV}
    assert_output -p 'volume serial : 0xc0ffee1'
}

@test "exfatlabel set volume label-t01" {
    run -0 ${LABEL_CMD} ${LOOP_DEV} label-t01
}

@test "exfatlabel get volume label-t01" {
    run -0 ${LABEL_CMD} ${LOOP_DEV}
    assert_output -p 'label: label-t01'
}

@test "tune.exfat set volume serial 2" {
    run -0 ${TUNE_CMD} -I 0xc0ffee2 ${LOOP_DEV}
}

@test "tune.exfat get volume serial 2" {
    run -0 ${TUNE_CMD} -i ${LOOP_DEV}
    assert_output -p 'volume serial : 0xc0ffee2'
}

@test "tune.exfat set volume label-t02" {
    run -0 ${TUNE_CMD} -L label-t02 ${LOOP_DEV}
}

@test "tune.exfat get volume label-t02" {
    run -0 ${TUNE_CMD} -l ${LOOP_DEV}
    assert_output -p 'label: label-t02'
}

@test "dump.exfat" {
    run -0 ${DUMP_CMD} ${LOOP_DEV}
}
