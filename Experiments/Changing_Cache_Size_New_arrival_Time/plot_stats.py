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

AVERAGE_NUM = 50
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
    time_list_LU6 = []
    data_list_LU6 = []
    new_data_list_LU6 = []
    time_list_LU7 = []
    data_list_LU7 = []
    new_data_list_LU7 = []
    time_list_LU8 = []
    data_list_LU8 = []
    new_data_list_LU8 = []

    with open("Exp_1/link_utilization_0_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU1.append(float(new_line[0]))
            data_list_LU1.append(float(new_line[1]))
    with open("Exp_2/link_utilization_8_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU2.append(float(new_line[0]))
            data_list_LU2.append(float(new_line[1]))
    
    with open("Exp_3/link_utilization_16_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU3.append(float(new_line[0]))
            data_list_LU3.append(float(new_line[1]))
    """
    with open("Exp_4/link_utilization_32_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU4.append(float(new_line[0]))
            data_list_LU4.append(float(new_line[1]))
    with open("Exp_5/link_utilization_64_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU5.append(float(new_line[0]))
            data_list_LU5.append(float(new_line[1]))
    with open("Exp_6/link_utilization_128_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU6.append(float(new_line[0]))
            data_list_LU6.append(float(new_line[1]))
    with open("Exp_7/link_utilization_256_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU7.append(float(new_line[0]))
            data_list_LU7.append(float(new_line[1]))
    """
    with open("Exp_8/link_utilization_1024_64_8.txt",'r') as file:
        for line in file:
            new_line = line[:-1]
            new_line = new_line[1:-1]
            new_line = new_line.split(",")
            new_line[1] = new_line[1][1:]
            time_list_LU8.append(float(new_line[0]))
            data_list_LU8.append(float(new_line[1]))

    for i in range(len(data_list_LU1)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU1.append(sum(data_list_LU1[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            time_list_LU1.remove(time_list_LU1[i])
    for i in range(len(data_list_LU2)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU2.append(sum(data_list_LU2[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            time_list_LU2.remove(time_list_LU2[i])
    for i in range(len(data_list_LU3)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU3.append(sum(data_list_LU3[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            time_list_LU3.remove(time_list_LU3[i])
    for i in range(len(data_list_LU4)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU4.append(sum(data_list_LU4[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            time_list_LU4.remove(time_list_LU4[i])
    for i in range(len(data_list_LU5)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU5.append(sum(data_list_LU5[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            time_list_LU5.remove(time_list_LU5[i])
    for i in range(len(data_list_LU6)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU6.append(sum(data_list_LU6[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            time_list_LU6.remove(time_list_LU6[i])
    for i in range(len(data_list_LU7)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU7.append(sum(data_list_LU7[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            time_list_LU7.remove(time_list_LU7[i])
    for i in range(len(data_list_LU8)):
        if (i>=AVERAGE_NUM):
            new_data_list_LU8.append(sum(data_list_LU8[i-AVERAGE_NUM:i])/AVERAGE_NUM)
        else:
            time_list_LU8.remove(time_list_LU8[i])




    ##########
    fig,(ax1,ax2) = plt.subplots(2,1)
    title ="Controller - Switch Link Utilization\n Miss Threshold = 64 \n Traffic arrival rate scaled to fit 600 sec"
    fig.suptitle(title)
    # make a plot
    ax1.plot(time_list_LU1,new_data_list_LU1,color='red')
    ax1.plot(time_list_LU2,new_data_list_LU2,color='green')
    ax1.plot(time_list_LU3,new_data_list_LU3,color='blue')
    #ax1.plot(time_list_LU4,new_data_list_LU4,color='green')
    #ax1.plot(time_list_LU5,new_data_list_LU5,color='')
    #ax1.plot(time_list_LU6,new_data_list_LU6,color='')
    #ax1.plot(time_list_LU7,new_data_list_LU7,color='')
    ax1.plot(time_list_LU8,new_data_list_LU8,color='brown')

    #ax2.plot(time_list_LU1,new_data_list_LU1,color='red')
    ax2.plot(time_list_LU2,new_data_list_LU2,color='green')
    ax2.plot(time_list_LU3,new_data_list_LU3,color='blue')
    #ax2.plot(time_list_LU4,new_data_list_LU4,color='')
    #ax2.plot(time_list_LU5,new_data_list_LU5,color='')
    #ax2.plot(time_list_LU6,new_data_list_LU6,color='')
    #ax2.plot(time_list_LU7,new_data_list_LU7,color='')
    ax2.plot(time_list_LU8,new_data_list_LU8,color='brown')


    #plt.title("Inserts and Deletes")
    #ax2.plot(time_list_deletions,new_data_list_deletions)
    #ax2.plot(time_list_deletions,new_data_list_insertions)
    #ax1.legend(["Cache Size = 32","Cache Size = 16","Cache Size = 8","Cache Size = 64","Cache Size = 128"])
    ax1.legend(["No Cache","Cache Size = 8","Cache Size = 16","Cache Size = 1024"])
    ax2.legend(["Cache Size = 8","Cache Size = 16","Cache Size = 1024"])

    #ax1.set_xlabel("Simulation Time [Seconds]",color="black",fontsize=12)
    #ax2.set_ylabel('Link Utilization [Packets]',color="black",fontsize=10)
    #ax1.set_ylabel('Link Utilization [Packets]',color="black",fontsize=12)
    fig.text(0.5, 0.04, 'Simulation Time [Seconds]', ha='center',fontsize=14)
    fig.text(0.07, 0.5, 'Link Utilization [Packets]', va='center', rotation='vertical',fontsize=14)
    fig.show()
    plt.show()


if __name__ == '__main__':
    main()
