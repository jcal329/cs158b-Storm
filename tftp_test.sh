#!/bin/bash
echo "run tftp test"
./make_zipapp.sh
python3 build/piman.pyz run-tftp-test
