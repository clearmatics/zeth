#!/bin/bash
# Script to run 50 integration tests

NOW=`date '+%F_%H:%M:%S'`;
filename="test_result_$NOW"

echo "Test started\n" >> $filename

for i in `seq 1 50`;
do
  python testEtherMixing.py PGHR13
  ret=$?

  if [ $ret -ne 0 ]; then
    echo "ETH test $i failed\n" >> $filename
  fi

  python testERCTokenMixing.py PGHR13
  ret=$?

  if [ $ret -ne 0 ]; then
    echo "Token test $i failed\n" >> $filename
  fi

echo "Test finished.\n" >> $filename
done
