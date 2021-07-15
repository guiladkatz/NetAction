s1 ./start_switch_cpu.sh 50005 48 64 16 1 &
h1 python tg.py &
h5 ./start_p4_controller.sh 200 64 16 30 50005