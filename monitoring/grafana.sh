#!/bin/bash

cd --
python3 -m pip install bottle

cd /usr/local/piman/monitoring
python3 grafana.py logs/monitor.log