#!/bin/sh

sudo python switch_cpu.py \
    --p4info net_action.p4info \
    --bmv2-json net_action.json \
    --my_topology topology.json
