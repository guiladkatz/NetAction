#!/usr/bin/env python
import argparse, grpc, sys, os, socket, random, struct, time

from time import sleep
import time
import Queue
import socket
import struct
from scapy.all import *
import matplotlib.pyplot as plt
import thread
import csv
from fcntl import ioctl
import IN

AVERAGE_NUM = 30
AVERAGE_NUM2 = 1

def main():

    time_list_LU1 = []
    data_list_LU1 = []
    new_data_list_LU1 = []
    time_list_LU2 = []
    data_list_LU2 = []
    new_data_list_LU2 = []
    time_list_LU3 = []
    data_list_LU3 = []
    new_data_list_LU3 = []
    time_list_LU4 = []
    data_list_LU4 = []
    new_data_list_LU4 = []
    time_list_LU5 = []
    data_list_LU5 = []
    new_data_list_LU5 = []

    with open("Exp_1/link_utilization_8_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU1.append(float(new_line[0]))
            data_list_LU1.append(float(new_line[1]))
    with open("Exp_2/link_utilization_16_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU2.append(float(new_line[0]))
            data_list_LU2.append(float(new_line[1]))
    with open("Exp_3/link_utilization_32_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU3.append(float(new_line[0]))
            data_list_LU3.append(float(new_line[1]))
    with open("Exp_4/link_utilization_64_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU4.append(float(new_line[0]))
            data_list_LU4.append(float(new_line[1]))
    with open("Exp_5/link_utilization_128_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU5.append(float(new_line[0]))
            data_list_LU5.append(float(new_line[1]))

    for i in range(len(data_list_LU1)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU1.append(sum(data_list_LU1[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            new_data_list_LU1.append(data_list_LU1[i])

    for i in range(len(data_list_LU2)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU2.append(sum(data_list_LU2[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            new_data_list_LU2.append(data_list_LU2[i])
    for i in range(len(data_list_LU3)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU3.append(sum(data_list_LU3[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            new_data_list_LU3.append(data_list_LU3[i])
    for i in range(len(data_list_LU4)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU4.append(sum(data_list_LU4[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            new_data_list_LU4.append(data_list_LU4[i])
    for i in range(len(data_list_LU5)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU5.append(sum(data_list_LU5[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            new_data_list_LU5.append(data_list_LU5[i])




    ##########
    fig,ax1 = plt.subplots()
    #title ="Cache Size = Varying\nController Miss Threshold = 64\nRandom Rules Sampling Number = Varying"
    #fig.suptitle(title)
    # make a plot
    ax1.plot(time_list_LU1,new_data_list_LU1)
    ax1.plot(time_list_LU2,new_data_list_LU2)
    #ax1.plot(time_list_LU3,new_data_list_LU3)
    #ax1.plot(time_list_LU4,new_data_list_LU4)
    #ax1.plot(time_list_LU5,new_data_list_LU5)

    # set x-axis label
    #ax1.set_xlabel("Simulation Time",fontsize=14)
    # set y-axis label
    ax1.set_ylabel("Link Utilization",color="red",fontsize=14)
    # make a plot
    #ax3=ax1.twinx()
    # make a plot with different y-axis using second axis object
    #ax3.plot(time_list_AR, new_data_list_LU,color="blue")
    #ax3.set_ylabel("Link Utilization",color="blue",fontsize=14)
    #plt.show()
    
    #plt.title("Inserts and Deletes")
    #ax2.plot(time_list_deletions,new_data_list_deletions)
    #ax2.plot(time_list_deletions,new_data_list_insertions)
    #ax1.legend(["Cache Size = 32","Cache Size = 16","Cache Size = 8","Cache Size = 64","Cache Size = 128"])
    ax1.legend(["Cache Size = 8","Cache Size = 16"])
    #ax2.set_xlabel("Simulation Time [Seconds]")
    #ax2.set_ylabel('Number of Events')
    fig.show()
    plt.show()


if __name__ == '__main__':
    main()
