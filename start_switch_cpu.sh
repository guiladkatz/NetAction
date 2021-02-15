#!/bin/sh

sudo python switch_cpu.py \
    --p4info basic_tutorial_switch.p4info \
    --bmv2-json basic_tutorial_switch.json \
    --my_topology topology.json
