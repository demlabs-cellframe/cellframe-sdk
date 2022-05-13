#!/usr/bin/env bash
if ! which make cc c++ tee >/dev/null; then
  echo "Please install the following prerequisites: make cc c++ tee banner" >&2
  exit 1
fi

LIST=--hill
FROM=1
UPTO=9999
MONITOR=
LOOPS=
SKIP_MAKE=no
BANNER="$(which banner 2>/dev/null | echo echo)"
UNAME="$(uname -s 2>/dev/null || echo Unknown)"
DB_UPTO_MB=17408

while [ -n "$1" ]
do
  case "$1" in
  --help)
    echo "--multi                Engage multi-process test scenario (default)"
    echo "--single               Execute series of single-process tests (for QEMU, etc)"
    echo "--with-valgrind        Run tests under Valgrind's memcheck tool"
    echo "--skip-make            Don't (re)build libmdbx and test's executable"
    echo "--from NN              Start iterating from the NN ops per test case"
    echo "--upto NN              Don't run tests with more than NN ops per test case"
    echo "--loops NN             Stop after the NN loops"
    echo "--dir PATH             Specifies directory for test DB and other files (it will be cleared)"
    echo "--db-upto-mb NN        Limits upper size of test DB to the NN megabytes"
    echo "--help                 Print this usage help and exit"
    exit -2
  ;;
  --multi)
    LIST=basic
  ;;
  --single)
    LIST="--nested --hill --append --ttl --copy"
  ;;
  --with-valgrind)
    echo " NOTE: Valgrind could produce some false-positive warnings"
    echo "       in multi-process environment with shared memory."
    echo "       For instance, when the process 'A' explicitly marks a memory"
    echo "       region as 'undefined', the process 'B' fill it,"
    echo "       and after this process 'A' read such region, etc."
    MONITOR="valgrind --trace-children=yes --log-file=valgrind-%p.log --leak-check=full --track-origins=yes --error-exitcode=42 --suppressions=test/valgrind_suppress.txt"
    rm -f valgrind-*.log
  ;;
  --skip-make)
    SKIP_MAKE=yes
  ;;
  --from)
    FROM=$(($2))
    if [ -z "$FROM" -o "$FROM" -lt 1 ]; then
      echo "Invalid value '$FROM' for --from option"
      exit -2
    fi
    shift
  ;;
  --upto)
    UPTO=$(($2))
    if [ -z "$UPTO" -o "$UPTO" -lt 1 ]; then
      echo "Invalid value '$UPTO' for --upto option"
      exit -2
    fi
    shift
  ;;
  --loops)
    LOOPS=$(($2))
    if [ -z "$LOOPS" -o "$LOOPS" -lt 1 -o "$LOOPS" -gt 99 ]; then
      echo "Invalid value '$LOOPS' for --loops option"
      exit -2
    fi
    shift
  ;;
  --dir)
    TESTDB_DIR="$2"
    if [ -z "$TESTDB_DIR" ]; then
      echo "Invalid value '$TESTDB_DIR' for --dir option"
      exit -2
    fi
    shift
  ;;
  --db-upto-mb)
    DB_UPTO_MB=$(($2))
    if [ -z "$DB_UPTO_MB" -o "$DB_UPTO_MB" -lt 1 -o "$DB_UPTO_MB" -gt 4194304 ]; then
      echo "Invalid value '$DB_UPTO_MB' for --db-upto-mb option"
      exit -2
    fi
    shift
  ;;
  *)
    echo "Unknown option '$1'"
    exit -2
  ;;
  esac
 shift
done

set -euo pipefail
if [ -z "$MONITOR" ]; then
  if which time >/dev/null 2>/dev/null; then
    MONITOR=$(which time)
    if $MONITOR -o /dev/stdout true >/dev/null 2>/dev/null; then
      MONITOR="$MONITOR -o /dev/stdout"
    fi
  fi
  export MALLOC_CHECK_=7 MALLOC_PERTURB_=42
fi

###############################################################################
# 1. clean data from prev runs and examine available RAM

WANNA_MOUNT=0
case ${UNAME} in
  Linux)
    MAKE=make
    if [ -z "${TESTDB_DIR:-}" ]; then
      for old_test_dir in $(ls -d /dev/shm/mdbx-test.[0-9]* 2>/dev/null); do
        rm -rf $old_test_dir
      done
      TESTDB_DIR="/dev/shm/mdbx-test.$$"
    fi
    mkdir -p $TESTDB_DIR && rm -f $TESTDB_DIR/*

    if LC_ALL=C free | grep -q -i available; then
      ram_avail_mb=$(($(LC_ALL=C free | grep -i Mem: | tr -s [:blank:] ' ' | cut -d ' ' -f 7) / 1024))
    else
      ram_avail_mb=$(($(LC_ALL=C free | grep -i Mem: | tr -s [:blank:] ' ' | cut -d ' ' -f 4) / 1024))
    fi
  ;;

  FreeBSD)
    MAKE=gmake
    if [ -z "${TESTDB_DIR:-}" ]; then
      for old_test_dir in $(ls -d /tmp/mdbx-test.[0-9]* 2>/dev/null); do
        umount $old_test_dir && rm -r $old_test_dir
      done
      TESTDB_DIR="/tmp/mdbx-test.$$"
      rm -rf $TESTDB_DIR && mkdir -p $TESTDB_DIR
      WANNA_MOUNT=1
    else
      mkdir -p $TESTDB_DIR && rm -f $TESTDB_DIR/*
    fi
    ram_avail_mb=$(($(LC_ALL=C vmstat -s | grep -ie '[0-9] pages free$' | cut -d p -f 1) * ($(LC_ALL=C vmstat -s | grep -ie '[0-9] bytes per page$' | cut -d b -f 1) / 1024) / 1024))
  ;;

  Darwin)
    MAKE=make
    if [ -z "${TESTDB_DIR:-}" ]; then
      for vol in $(ls -d /Volumes/mdx[0-9]*[0-9]tst 2>/dev/null); do
        disk=$(mount | grep $vol | cut -d ' ' -f 1)
        echo "umount: volume $vol disk $disk"
        hdiutil unmount $vol -force
        hdiutil detach $disk
      done
      TESTDB_DIR="/Volumes/mdx$$tst"
      WANNA_MOUNT=1
    else
      mkdir -p $TESTDB_DIR && rm -f $TESTDB_DIR/*
    fi
    pagesize=$(($(LC_ALL=C vm_stat | grep -o 'page size of [0-9]\+ bytes' | cut -d' ' -f 4) / 1024))
    freepages=$(LC_ALL=C vm_stat | grep '^Pages free:' | grep -o '[0-9]\+\.$' | cut -d'.' -f 1)
    ram_avail_mb=$((pagesize * freepages / 1024))
    echo "pagesize ${pagesize}K, freepages ${freepages}, ram_avail_mb ${ram_avail_mb}"
  ;;

  *)
    echo "FIXME: ${UNAME} not supported by this script"
    exit 2
  ;;
esac

rm -f ${TESTDB_DIR}/*

###############################################################################
# 2. estimate reasonable RAM space for test-db

echo "=== ${ram_avail_mb}M RAM available"
ram_reserve4logs_mb=1234
if [ $ram_avail_mb -lt $ram_reserve4logs_mb ]; then
  echo "=== At least ${ram_reserve4logs_mb}Mb RAM required"
  exit 3
fi

#
# В режимах отличных от MDBX_WRITEMAP изменения до записи в файл
# будут накапливаться в памяти, что может потребовать свободной
# памяти размером с БД. Кроме этого, в тест входит сценарий
# создания копия БД на ходу. Поэтому БД не может быть больше 1/3
# от доступной памяти. Однако, следует учесть что malloc() будет
# не сразу возвращать выделенную память системе, а также
# предусмотреть места для логов.
#
# In non-MDBX_WRITEMAP modes, updates (dirty pages) will
# accumulate in memory before writing to the disk, which may
# require a free memory up to the size of a whole database. In
# addition, the test includes a script create a copy of the
# database on the go. Therefore, the database cannot be more 1/3
# of available memory. Moreover, should be taken into account
# that malloc() will not return the allocated memory to the
# system immediately, as well some space is required for logs.
#
db_size_mb=$(((ram_avail_mb - ram_reserve4logs_mb) / 4))
if [ $db_size_mb -gt $DB_UPTO_MB ]; then
  db_size_mb=$DB_UPTO_MB
fi
echo "=== use ${db_size_mb}M for DB"

###############################################################################
# 3. Create test-directory in ramfs/tmpfs, i.e. create/format/mount if required
case ${UNAME} in
  Linux)
    ulimit -c unlimited
    if [ "$(cat /proc/sys/kernel/core_pattern)" != "core.%p" ]; then
      echo "core.%p > /proc/sys/kernel/core_pattern" >&2
      echo "core.%p" | sudo tee /proc/sys/kernel/core_pattern || true
    fi
  ;;

  FreeBSD)
    if [[ WANNA_MOUNT ]]; then
      mount -t tmpfs tmpfs $TESTDB_DIR
    fi
  ;;

  Darwin)
    if [[ WANNA_MOUNT ]]; then
      ramdisk_size_mb=$((42 + db_size_mb * 2 + ram_reserve4logs_mb))
      number_of_sectors=$((ramdisk_size_mb * 2048))
      ramdev=$(hdiutil attach -nomount ram://${number_of_sectors})
      diskutil erasevolume ExFAT "mdx$$tst" ${ramdev}
    fi
  ;;

  *)
    echo "FIXME: ${UNAME} not supported by this script"
    exit 2
  ;;
esac

###############################################################################
# 4. build the test executables

if [ "$SKIP_MAKE" != "yes" ]; then
  ${MAKE} -j$(which nproc  >/dev/null 2>/dev/null && nproc || echo 2) build-test
fi

###############################################################################
# 5. run stochastic iterations

if which lz4 >/dev/null; then
  function logger {
    lz4 > ${TESTDB_DIR}/long.log.lz4
  }
elif which gzip >/dev/null; then
  function logger {
    gzip > ${TESTDB_DIR}/long.log.gz
  }
else
  function logger {
    cat > ${TESTDB_DIR}/long.log
  }
fi

syncmodes=("" ,+nosync-safe ,+nosync-utterly)
options=(writemap coalesce lifo notls perturb)

function join { local IFS="$1"; shift; echo "$*"; }

function bits2options {
  local bits=$1
  local i
  local list=()
  for ((i = 0; i < ${#options[@]}; ++i)); do
    list[$i]=$( (( (bits & (1 << i)) != 0 )) && echo -n '+' || echo -n '-'; echo ${options[$i]})
  done
  join , ${list[@]}
}

function failed {
  echo "FAILED" >&2
  exit 1
}

function check_deep {
  if [ "$case" = "basic" -o "$case" = "--hill" ]; then
    tee >(logger) | grep -e reach -e achieve
  else
    logger
  fi
}

function probe {
  echo "----------------------------------------------- $(date)"
  echo "${caption}"
  rm -f ${TESTDB_DIR}/* || failed
  for case in $LIST
  do
    echo "Run ./mdbx_test ${speculum} --random-writemap=no --ignore-dbfull --repeat=1 --pathname=${TESTDB_DIR}/long.db --cleanup-after=no $@ $case"
    ${MONITOR} ./mdbx_test ${speculum} --random-writemap=no --ignore-dbfull --repeat=1 --pathname=${TESTDB_DIR}/long.db --cleanup-before=yes --cleanup-after=no "$@" $case | check_deep \
      && ${MONITOR} ./mdbx_chk ${TESTDB_DIR}/long.db | tee ${TESTDB_DIR}/long-chk.log \
      && ([ ! -e ${TESTDB_DIR}/long.db-copy ] || ${MONITOR} ./mdbx_chk ${TESTDB_DIR}/long.db-copy | tee ${TESTDB_DIR}/long-chk-copy.log) \
      || failed
   done
}

#------------------------------------------------------------------------------

count=0
loop=0
cases='?'
for ((wbatch=FROM; wbatch<=UPTO; ++wbatch)); do
  if [ -n "$LOOPS" ] && [ $loop -ge "$LOOPS" ]; then echo "The '--loops $LOOPS' limit reached"; break; fi
  echo "======================================================================="
  speculum=$([ $wbatch -le 1000 ] && echo '--speculum' || true)
  nops=$((wbatch/7 + 1))
  for ((rep=1; rep < 11; ++rep)); do
    echo "======================================================================="
    ${BANNER} "$nops / $wbatch, repeat $rep"
    subcase=0
    for ((bits=2**${#options[@]}; --bits >= 0; )); do
      seed=$(($(date +%s) + RANDOM))

      split=30
      caption="Probe #$((++count)) int-key,int-data, split=${split}, case $((++subcase)) of ${cases}" probe \
        --pagesize=4K --size-upper-upto=${db_size_mb}M --table=+key.integer,+data.integer --keygen.split=${split} --keylen.min=min --keylen.max=max --datalen.min=min --datalen.max=max \
        --nops=$nops --batch.write=$wbatch --mode=$(bits2options $bits)${syncmodes[count%3]} \
        --keygen.seed=${seed}

      split=24
      caption="Probe #$((++count)) int-key,int-data, split=${split}, case $((++subcase)) of ${cases}" probe \
        --pagesize=4K --size-upper-upto=${db_size_mb}M --table=+key.integer,+data.integer --keygen.split=${split} --keylen.min=min --keylen.max=max --datalen.min=min --datalen.max=max \
        --nops=$nops --batch.write=$wbatch --mode=$(bits2options $bits)${syncmodes[count%3]} \
        --keygen.seed=${seed}

      split=16
      caption="Probe #$((++count)) int-key,w/o-dups, split=${split}, case $((++subcase)) of ${cases}" probe \
        --pagesize=4K --size-upper-upto=${db_size_mb}M --table=+key.integer,-data.dups --keygen.split=${split} --keylen.min=min --keylen.max=max --datalen.min=min --datalen.max=1111 \
        --nops=$nops --batch.write=$wbatch --mode=$(bits2options $bits)${syncmodes[count%3]} \
        --keygen.seed=${seed}
      caption="Probe #$((++count)) int-key,int-data, split=${split}, case $((++subcase)) of ${cases}" probe \
        --pagesize=4K --size-upper-upto=${db_size_mb}M --table=+key.integer,+data.integer --keygen.split=${split} --keylen.min=min --keylen.max=max --datalen.min=min --datalen.max=max \
        --nops=$nops --batch.write=$wbatch --mode=$(bits2options $bits)${syncmodes[count%3]} \
        --keygen.seed=${seed}
      caption="Probe #$((++count)) w/o-dups, split=${split}, case $((++subcase)) of ${cases}" probe \
        --pagesize=4K --size-upper-upto=${db_size_mb}M --table=-data.dups --keygen.split=${split} --keylen.min=min --keylen.max=max --datalen.min=min --datalen.max=1111 \
        --nops=$nops --batch.write=$wbatch --mode=$(bits2options $bits)${syncmodes[count%3]} \
        --keygen.seed=${seed}

      split=4
      caption="Probe #$((++count)) int-key,w/o-dups, split=${split}, case $((++subcase)) of ${cases}" probe \
        --pagesize=4K --size-upper-upto=${db_size_mb}M --table=+key.integer,-data.dups --keygen.split=${split} --keylen.min=min --keylen.max=max --datalen.min=min --datalen.max=1111 \
        --nops=$nops --batch.write=$wbatch --mode=$(bits2options $bits)${syncmodes[count%3]} \
        --keygen.seed=${seed}
      caption="Probe #$((++count)) int-key,int-data, split=${split}, case $((++subcase)) of ${cases}" probe \
        --pagesize=4K --size-upper-upto=${db_size_mb}M --table=+key.integer,+data.integer --keygen.split=${split} --keylen.min=min --keylen.max=max --datalen.min=min --datalen.max=max \
        --nops=$nops --batch.write=$wbatch --mode=$(bits2options $bits)${syncmodes[count%3]} \
        --keygen.seed=${seed}
      caption="Probe #$((++count)) w/o-dups, split=${split}, case $((++subcase)) of ${cases}" probe \
        --pagesize=4K --size-upper-upto=${db_size_mb}M --table=-data.dups --keygen.split=${split} --keylen.min=min --keylen.max=max --datalen.min=min --datalen.max=1111 \
        --nops=$nops --batch.write=$wbatch --mode=$(bits2options $bits)${syncmodes[count%3]} \
        --keygen.seed=${seed}
    done # options
    cases="${subcase}"
  done # repeats
  loop=$((loop + 1))
  if [ -n "$LOOPS" ] && [ $loop -ge "$LOOPS" ]; then break; fi
done # wbatch

echo "=== ALL DONE ====================== $(date)"
