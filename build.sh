#!/bin/sh

# Step 1: Clean previous processes
sudo mn -c
# Step 1: Create *.json and *.p4info
make

# Step 2: Assign those deps to ../../lib/main.py
#       - topology.json
#       - *.p4.json
#       - "simple_switch_grpc"
sudo python ../../../utils/run_exercise.py \
    --topo topology.json \
    --switch_json net_action.json \
    --behavioral-exe simple_switch_grpc \
    --threshold $1 \
    --cache_size $2 \
    --random_rules_num $3 \
    --run_time $4 \
    --port $5 \
    --eviction_threshold $6 \
    --read_counter_interval $7

#PORT=$(($PORT+1))
#echo $PORT

#sleep 5

#sudo mn -c
#sudo netstat -np | grep 50000 | awk '{print $1}'

#sudo python ../../../utils/run_exercise.py \
#    --topo topology.json \
#    --switch_json net_action.json \
#    --behavioral-exe simple_switch_grpc \
#    --threshold 256 \
#    --cache_size 32 \
#    --random_rules_num 16 \
#    --run_time 5 \
#    --port 50008