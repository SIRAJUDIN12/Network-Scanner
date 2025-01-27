# -*- coding: utf-8 -*-
"""
Created on Mon Jan 27 10:39:49 2025

@author: Hp
"""

import csv
from scapy.all import ARP, Ether, srp
import socket
import threading
from queue import Queue
import tkinter as tk
from tkinter import filedialog, messagebox


# Function to scan the network for connected devices
def network_scan(ip_range):
    devices = []
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


# Threaded port scanning
def threaded_port_scan(ip, port_range):
    open_ports = []

    def worker():
        while not port_queue.empty():
            port = port_queue.get()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
            port_queue.task_done()

    # Create a queue of ports
    port_queue = Queue()
    for port in range(port_range[0], port_range[1] + 1):
        port_queue.put(port)

    # Start threads
    threads = []
    for _ in range(10):  # 10 threads
        thread = threading.Thread(target=worker)
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    return open_ports


# Function to save results to a CSV file
def save_results_to_csv(devices_with_ports):
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
    )
    if file_path:
        with open(file_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["IP Address", "MAC Address", "Open Ports"])
            for device in devices_with_ports:
                writer.writerow([device["ip"], device["mac"], ", ".join(map(str, device["open_ports"]))])
        messagebox.showinfo("Success", "Results saved to CSV file!")


# Function to run the scan and display results
def run_scan():
    ip_range = ip_range_entry.get()
    port_start = int(port_start_entry.get())
    port_end = int(port_end_entry.get())

    devices = network_scan(ip_range)
    devices_with_ports = []

    for device in devices:
        open_ports = threaded_port_scan(device["ip"], (port_start, port_end))
        device["open_ports"] = open_ports
        devices_with_ports.append(device)

    # Display results
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, f"{'IP Address':<20}{'MAC Address':<20}{'Open Ports'}\n")
    result_text.insert(tk.END, "-" * 60 + "\n")
    for device in devices_with_ports:
        result_text.insert(
            tk.END, f"{device['ip']:<20}{device['mac']:<20}{', '.join(map(str, device['open_ports']))}\n"
        )

    # Save results to CSV
    save_button.config(command=lambda: save_results_to_csv(devices_with_ports))


# GUI Setup
app = tk.Tk()
app.title(" Network Scanner")
app.geometry("600x400")

# Input fields
tk.Label(app, text="Enter the network range (e.g., 192.168.1.0/24):").pack(pady=5)
ip_range_entry = tk.Entry(app, width=40)
ip_range_entry.pack(pady=5)

tk.Label(app, text="Enter the starting port:").pack(pady=5)
port_start_entry = tk.Entry(app, width=20)
port_start_entry.pack(pady=5)

tk.Label(app, text="Enter the ending port:").pack(pady=5)
port_end_entry = tk.Entry(app, width=20)
port_end_entry.pack(pady=5)

# Run scan button
run_button = tk.Button(app, text="Run Scan", command=run_scan, bg="blue", fg="white")
run_button.pack(pady=10)

# Results display
result_text = tk.Text(app, height=10, width=70)
result_text.pack(pady=10)

# Save button
save_button = tk.Button(app, text="Save Results to CSV", bg="green", fg="white")
save_button.pack(pady=5)

# Run the app
app.mainloop()
