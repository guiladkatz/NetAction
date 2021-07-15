import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import csv
import copy
import time
import json
import ipaddress
import pickle
import operator
from Policy import Policy
from time import sleep


class Utils(object):
    @staticmethod
    def search_interval_array(interval_dict, value):
        interval_array = list(interval_dict.keys())
        low, high = 0, len(interval_array) - 1
        while (low < high):
            mid = int((high + low) / 2)
            # print("low = " + str(low) + " high = " + str(high) + " mid = " + str(mid))

            if value in interval_array[mid]:
                return interval_dict[interval_array[mid]]
            if value < interval_array[mid].right:
                high = mid
            if value > interval_array[mid].left:
                low = mid
        print("Error!")
        return None

    @staticmethod
    def run_pareto_visualization():
        alphas = [1, 1.5, 1.7, 2]
        x_ms = [1, 1.5, 1.7, 2]
        n_exp = 1000
        for a in alphas:
            for x_m in x_ms:
                data = np.sort((np.random.pareto(a, n_exp) + 1) * x_m)
                PlotTG.plot_xy(range(n_exp), data, "Sample Index", "Sample Value",
                               "Pareto Distribution for alpha = " + str(a) + " x_m = " + str(x_m))
                PlotTG.plot_cdf(data, "Sample Value",
                                "CDF Of Pareto Distribution for alpha = " + str(a) + " x_m = " + str(x_m))


class PlotTG(object):
    @staticmethod
    def plot_xy(x_data, y_data, x_label, y_label, title):
        plt.clf()
        fig, ax = plt.subplots()
        plt.xlabel(x_label)
        plt.ylabel(y_label)
        plt.title(title)
        ax.plot(x_data, y_data)
        plt.tight_layout()
        fig.show()

    @staticmethod
    def plot_cdf(data, data_x="data", data_title="title"):
        x = np.linspace(min(data), max(data), 101)
        count_dict = {i: 0 for i in x}
        for i in x:
            for j in data:
                if j < i:
                    count_dict[i] += 1
        max_n = max(count_dict.values())
        plt.clf()
        fig, ax = plt.subplots()
        plt.xlabel(data_x)
        plt.ylabel("CDF")
        plt.title(data_title)
        ax.plot(count_dict.keys(), [i / max_n for i in count_dict.values()])
        plt.tight_layout()
        fig.show()

    @staticmethod
    def plot_grayscacle_heatmap(prob_df):
        prob_mtx = prob_df.to_numpy()
        # 0 - black 255 - white
        max_n = max([max(row) for row in prob_mtx])
        mean = lambda x: sum(x) / len(x)
        mean_n = mean([mean(row) for row in prob_mtx])
        # normalize
        gs_matrix1 = [[np.uint8((1 - (i / mean_n) * 1e15) * 255) for i in row] for row in prob_mtx]
        gs_matrix2 = [[np.uint8((1 - (i / max_n) * 1e15) * 255) for i in row] for row in prob_mtx]

        fig, ax = plt.subplots()
        ax = plt.imshow(gs_matrix1, cmap='gray')
        plt.show()

        fig, ax = plt.subplots()
        ax = plt.imshow(gs_matrix2, cmap='gray')
        plt.show()

    @staticmethod
    def plot_array(data, title, x_label, y_label, sort=True):
        plt.clf()
        fig, ax = plt.subplots()
        plt.xlabel(x_label)
        plt.ylabel(y_label)
        plt.title(title)
        if sort:
            ax.plot(range(1, len(data) + 1), np.sort(data))
        else:
            ax.plot(range(1, len(data) + 1), data)
        fig.show()

    @staticmethod
    def generate_probabilities_matrix(flow_array):
        # Rows correspond to source racks and columns to destination racks - ProjecToR
        # Pr(SRC = s, DST = d) == Pr(SRC = s)*Pr(DST = d) i.i.d
        ips, pair_flow_size = set(), dict()
        for tp in flow_array:  # tp = src_ip, dst_ip, flow_size, flow_id
            src_ip, dst_ip, flow_size = str(tp[0]), str(tp[1]), int(tp[2])
            ips.add(src_ip)
            ips.add(dst_ip)
            # save new or aggregate
            pair_flow_size[(src_ip, dst_ip)] = flow_size if pair_flow_size.get(
                (src_ip, dst_ip)) is None else pair_flow_size[(src_ip, dst_ip)] + flow_size
        total_flow_size = sum([tp[2] for tp in flow_array])
        df_dict = {}
        for ip_dst in ips:
            curr_column = []
            for ip_src in ips:
                flow_size = pair_flow_size.get((ip_src, ip_dst))
                connection_probability = float(flow_size / total_flow_size) if flow_size is not None else 0.0
                curr_column.append(connection_probability)
            df_dict[ip_dst] = curr_column
        df = pd.DataFrame.from_dict(df_dict)
        return df


class TrafficMatrix(object):
    def __init__(self, n, alpha, x_m):
        self.src_dist = np.sort(np.random.pareto(alpha, n + 1) * x_m)  # n intervals
        self.dst_dist = np.sort(np.random.pareto(alpha, n + 1) * x_m)  # n intervals
        src_interval_array = pd.arrays.IntervalArray.from_arrays(self.src_dist[:-1], self.src_dist[1:])
        dst_interval_array = pd.arrays.IntervalArray.from_arrays(self.dst_dist[:-1], self.dst_dist[1:])
        self.hosts = [i for i in range(n)]
        self.src = {interval: host for interval, host in zip(src_interval_array, self.hosts)}
        self.dst = {interval: host for interval, host in zip(dst_interval_array, self.hosts)}
        self.traffic_matrix = self.generate_probabilities_matrix()

    def generate_pair(self):
        src = TrafficMatrix.choose_host(self.src, self.src_dist)
        dst = TrafficMatrix.choose_host(self.dst, self.dst_dist, [src])
        return src, dst

    def generate_probabilities_matrix(self):
        # Rows correspond to source racks and columns to destination racks - ProjecToR
        # Pr(SRC = s, DST = d) == Pr(SRC = s)*Pr(DST = d) i.i.d
        length_src = max(self.src_dist) - min(self.src_dist)
        src_prob = [iv.length / length_src for iv in self.src.keys()]  # Pr(SRC = s)
        length_dst = max(self.dst_dist) - min(self.dst_dist)
        dst_prob = [iv.length / length_dst for iv in self.dst.keys()]  # Pr(DST = d)
        data = {}
        for i in range(len(src_prob)):
            data["Host " + str(i)] = [int(i != j) * src_prob[i] * dst_prob[j] for j in range(len(dst_prob))]

        hosts = ["Host " + str(i) for i in range(len(dst_prob))]  # len(src_prob) == len(dst_prob)
        prob_matrix = pd.DataFrame.from_dict(data, orient='index',
                                             columns=hosts)
        return prob_matrix

    @staticmethod
    def choose_host(host_interval_dict, dist, exclude=[]):
        low, high = min(dist), max(dist)
        while True:
            random_n = np.random.uniform(low, high)
            for interval in host_interval_dict.keys():
                if random_n in interval and host_interval_dict[interval] not in exclude:
                    return host_interval_dict[interval]
        return None

    @staticmethod
    def print_matrix(mtx):
        cols = ["Host " + str(i) for i in range(1, len(mtx[0]) + 1)]
        df = pd.DataFrame(mtx, columns=cols, index=cols)
        print(df)


class FlowSize(object):

    def __init__(self, path=None, n=None, alpha=None, x_m=None):
        if path:
            self.source = "from_file"
            df = pd.read_csv(path, header=[0])
            flow_size_header, cdf_header = df.columns
            if df[cdf_header][0] != 0:  # need to insert 0 in the first row for completness
                df.loc[-1] = [0, 0]
                df.index = df.index + 1
                df = df.sort_index()
            interval_array = pd.arrays.IntervalArray.from_arrays(df[cdf_header][:-1], df[cdf_header][1:])
            self.flow_size_distribution = {interval: size for interval, size in
                                           zip(interval_array, df[flow_size_header])}
        else:
            self.source = "random_sample"
            flow_size_distribution = (np.random.pareto(alpha, n) + 1) * x_m  # pareto distribution
            max_pd = max(flow_size_distribution)
            flow_size_distribution = [i / max_pd for i in flow_size_distribution]
            scale = 1e3  # KB
            self.flow_size_distribution = [i * scale for i in flow_size_distribution]

    def choose_flow_size(self):
        if "random_sample" in self.source:
            return self.flow_size_distribution[np.random.randint(0, len(self.flow_size_distribution) - 1)]
        else:
            rand_n = np.random.rand()  # random samples from a uniform distribution over ``[0, 1)``.
            return Utils.search_interval_array(self.flow_size_distribution, rand_n)

    def calculate_pdf(self, path):
        flowsize_cdf = {}
        with open(path, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=',', quotechar='|')
            next(reader)  # skip headers
            for row in reader:
                flowsize_cdf[float(row[0])] = float(row[1])
        curr_cdf = 0
        curr_size = 0
        flowsize_pdf = {}
        for flow_size in flowsize_cdf.keys():  # sorted by size
            flowsize_pdf[(float(curr_size), float(flow_size))] = float(flowsize_cdf[flow_size]) - float(curr_cdf)
            curr_cdf = flowsize_cdf[flow_size]
            curr_size = flow_size
        return flowsize_pdf


class TrafficGenerator(object):
    def __init__(self, n, alpha, x_m, path=None, flow_array_json=None):
        self.flow_size = FlowSize(path, n, alpha, x_m)
        if flow_array_json:
            with open(flow_array_json) as f:
                data = json.load(f)
                self.flow_array = [(ipaddress.ip_address(tp[0]), ipaddress.ip_address(tp[1]), int(tp[2]), int(tp[3]))
                                   for tp in data]
        else:
            self.flow_array = []
            self.clock = 0

    def generate_flow_array(self, n_flows, policy):
        for i in range(n_flows):
            src_ip, dst_ip = 0, 0
            while src_ip == dst_ip:
                src_ip = policy.get_random_ip()
                dst_ip = policy.get_random_ip()

            data = (src_ip, dst_ip, self.flow_size.choose_flow_size(), self.clock, i)
            self.flow_array.append(data)
            self.clock += np.random.exponential(1)

    def generate_packets(self):
        packet_array = []
        MTU = 128
        for flow in self.flow_array:
            src_ip, dst_ip, flow_size, start_time, flow_id = flow
            while flow_size > 0:
                packet_start_time = start_time
                paceket_size = min(MTU, flow_size)
                flow_size = flow_size - paceket_size
                packet = (src_ip, dst_ip, paceket_size, packet_start_time, flow_id)
                packet_start_time += np.random.exponential(1)
                packet_array.append(packet)

        return sorted(packet_array, key=lambda packet: packet[3])

    def save_flow_array_to_json(self, path):
        with open(path, 'w+') as outfile:
            json.dump([(str(tp[0]), str(tp[1]), str(tp[2]), str(tp[3])) for tp in self.flow_array], outfile)

    def show(self, flow_distribution_title):
        print("-------------- Plotting CDF --------------")
        if "from_file" in self.flow_size.source:
            PlotTG.plot_xy(self.flow_size.flow_size_distribution.values(),
                           [iv.left for iv in self.flow_size.flow_size_distribution], "Flow Size", "CDF",
                           "Flow Size Distribution - " + flow_distribution_title)
        else:
            PlotTG.plot_cdf(self.flow_size.flow_size_distribution, "Flow Size",
                            "Flow Size Distribution - " + flow_distribution_title)

        print("-------------- Plotting Garyscale Heatmap --------------")
        PlotTG.plot_grayscacle_heatmap(self.traffic_matrix.generate_probabilities_matrix())



def main():
    n_host = 10
    n_flows = 1000
    init_alpha = 3
    init_x_m = 1
    flow_dict = {}
    p = Policy('https://www.cidr-report.org/cgi-bin/as-report?as=AS16509&view=2.0', 'data/policy/AS16509.json')
    p.init_subnets()
    # Building the cidr-trie
    p.build_trie()
    p.build_extended_trie()
    tg1 = TrafficGenerator(n_host, init_alpha, init_x_m, "data/traffic/others/Fabricated_Heavy_Head.csv")
    tg1.generate_flow_array(n_flows, p)
    #print("----------------- FLOWS -----------------")
    #for flow in tg1.flow_array:
    #    print(flow)
    with open('flows.csv', 'w', newline='') as file1:
        writer = csv.writer(file1)
        writer.writerow(["Source", "Destination", "Size","Arrival Time","Flow ID"])
        for flow in tg1.flow_array:
            ip_val = str(p.seek_for_match_new(flow[1])[0])
            if (ip_val == None) or (ip_val == "None"):
                ip_val = str(flow[1]) + "/32"
            flow_dict[str(flow[1])] = ip_val
            writer.writerow(flow)

    sorted_array = sorted(tg1.flow_array,key=operator.itemgetter(2),reverse=True)
    with open('flows_sorted_by_size.csv', 'w', newline='') as file2:
        writer2 = csv.writer(file2)
        writer2.writerow(["Source", "Destination", "Size","Arrival Time","Flow ID"])
        for new_flow in sorted_array:
            writer2.writerow(new_flow)

    with open('flow_rule_dict.pickle', 'wb') as handle:
        pickle.dump(flow_dict, handle, protocol=2)
    
    print("Finished creating Policy and Flows files")

    """
    for node in p.policy_ptrie.traverse_preorder():
        rule_ip = str(ipaddress.ip_network(node.ip)).split("/")[0]
        if rule_ip != "0.0.0.0":
            node_mask = str(list(node.masks.keys())[0])
            rule = rule_ip + "/" + node_mask
            print(rule)
    """

    #packets = tg1.generate_packets()
    #t2_t = time.time()
    #print(len(packets))

    #print("----------------- PACKETS -----------------")
    #for packet in packets:
    #    print(packet)

    """
    with open('packets.csv', 'w', newline='') as file2:
        writer = csv.writer(file2)
        writer.writerow(["Source", "Destination", "Size","Arrival Time","Flow ID"])
        for packet in packets:
            writer.writerow(packet)
        print("end2")

    sleep(2)
    """
    """
    with open('packets.csv', newline='') as csvfile:
        spamreader = csv.reader(csvfile, quotechar='|')
        for row in spamreader:
            print(row[0])
            print(row[1])
            print(row[2])
            print(row[3])
            #print(', '.join(row))
        #writer.writerow(["SN", "Name", "Contribution"])
        #writer.writerow([1, "Linus Torvalds", "Linux Kernel"])
        #writer.writerow([2, "Tim Berners-Lee", "World Wide Web"])
        #writer.writerow([3, "Guido van Rossum", "Python Programming"])
    """


    
    # t1 = time.time()
    # tg1.generate_flow_array(100, p)  # 1000 - 21 sec - choose flow size is binary search
    # tg1.save_flow_array_to_json('data/genereated_flow.json')
    # t2 = time.time()
    # print(str(t2 - t1))
    # tg2 = TrafficGenerator(n_host, init_alpha, init_x_m, "data/traffic/others/Fabricated_Heavy_Head.csv",
    #                        'data/genereated_flow.json')
    #
    # prob_mtx = PlotTG.generate_probabilities_matrix(tg2.flow_array)
    # PlotTG.plot_grayscacle_heatmap(prob_mtx)
    # t1_t = time.time()
    # packets = tg2.generate_packets()
    # t2_t = time.time()
    # print("tg2.generate_packets(): " + str(t2_t - t1_t))
    # print(len(packets))
    # for packet in packets:
    #     print(packet)


if __name__ == "__main__":
    main()
