# Save as analyze_tcp.py
import subprocess
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import os
import re

# List all manual pcap files
pcap_files = [f for f in os.listdir('.') if f.startswith('manual_') and f.endswith('.pcap')]
print(f"Found PCAP files: {', '.join(pcap_files)}")

# Function to run tshark command safely and get output
def run_tshark(cmd):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stderr and "error" in result.stderr.lower():
        print(f"Warning: tshark reported an error: {result.stderr}")
    return result.stdout

# Function to check if iperf is present in the pcap
def check_for_iperf(pcap_file):
    # Look for iperf ports (5201 is standard)
    cmd = f"tshark -r {pcap_file} -Y \"tcp.port == 5201\" | head -1"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return bool(result.stdout.strip())

# Function to identify unique TCP flows in the pcap file
def get_tcp_flows(pcap_file):
    # Get all TCP conversations
    cmd = f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -Y \"tcp && tcp.port==5201\" | sort | uniq"
    output = run_tshark(cmd)
    
    flows = []
    for line in output.strip().split('\n'):
        if not line.strip():
            continue
            
        parts = line.strip().split('\t')
        if len(parts) >= 4:
            src_ip = parts[0]
            dst_ip = parts[1]
            src_port = parts[2]
            dst_port = parts[3]
            
            # Check if this flow is an iperf flow (using port 5201)
            if src_port == '5201': # Server to client flow
                flows.append({
                    'server_ip': src_ip,
                    'client_ip': dst_ip,
                    'server_port': src_port,
                    'client_port': dst_port,
                    'flow': f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                    'direction': 'server_to_client'
                })
            else: # Client to server flow
                flows.append({
                    'server_ip': dst_ip,
                    'client_ip': src_ip,
                    'server_port': dst_port,
                    'client_port': src_port,
                    'flow': f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                    'direction': 'client_to_server'
                })
    
    print(f"Found {len(flows)} iperf flows")
    return flows

# Function to calculate duration of a flow
def get_flow_duration(pcap_file, flow):
    filter_exp = f"ip.addr=={flow['server_ip']} && ip.addr=={flow['client_ip']} && tcp.port=={flow['server_port']}"
    cmd = f"tshark -r {pcap_file} -Y \"{filter_exp}\" -T fields -e frame.time_epoch | sort"
    output = run_tshark(cmd)
    
    times = []
    for line in output.strip().split('\n'):
        if line.strip():
            try:
                times.append(float(line.strip()))
            except ValueError:
                continue
    
    if times and len(times) > 1:
        duration = max(times) - min(times)
        return duration
    return 10.0  # Default to 10 seconds if we can't determine

# Function to calculate bytes transferred in a flow
def get_flow_bytes(pcap_file, flow):
    # Consider measuring actual data bytes, not including headers
    filter_exp = f"ip.addr=={flow['server_ip']} && ip.addr=={flow['client_ip']} && tcp.port=={flow['server_port']}"
    cmd = f"tshark -r {pcap_file} -Y \"{filter_exp}\" -T fields -e tcp.len | awk '{{sum+=$1}} END {{print sum}}'"
    output = run_tshark(cmd)
    
    if output.strip():
        try:
            return int(output.strip())
        except ValueError:
            return 0
    return 0

# Function to calculate goodput (payload bytes excluding retransmissions)
def get_flow_goodput(pcap_file, flow):
    # Exclude retransmissions when measuring goodput
    filter_exp = f"ip.addr=={flow['server_ip']} && ip.addr=={flow['client_ip']} && tcp.port=={flow['server_port']} && !tcp.analysis.retransmission"
    cmd = f"tshark -r {pcap_file} -Y \"{filter_exp}\" -T fields -e tcp.len | awk '{{sum+=$1}} END {{print sum}}'"
    output = run_tshark(cmd)
    
    if output.strip():
        try:
            return int(output.strip())
        except ValueError:
            return 0
    return 0

# Function to calculate packet loss rate
def get_flow_loss_rate(pcap_file, flow):
    # Count retransmissions
    filter_exp = f"ip.addr=={flow['server_ip']} && ip.addr=={flow['client_ip']} && tcp.port=={flow['server_port']} && tcp.analysis.retransmission"
    cmd = f"tshark -r {pcap_file} -Y \"{filter_exp}\" | wc -l"
    retrans_output = run_tshark(cmd)
    retransmissions = int(retrans_output.strip()) if retrans_output.strip() else 0
    
    # Count total packets
    filter_exp = f"ip.addr=={flow['server_ip']} && ip.addr=={flow['client_ip']} && tcp.port=={flow['server_port']}"
    cmd = f"tshark -r {pcap_file} -Y \"{filter_exp}\" | wc -l"
    total_output = run_tshark(cmd)
    total_packets = int(total_output.strip()) if total_output.strip() else 0
    
    if total_packets > 0:
        return retransmissions / total_packets
    return 0

# Function to get maximum window size
def get_max_window_size(pcap_file, flow):
    filter_exp = f"ip.addr=={flow['server_ip']} && ip.addr=={flow['client_ip']} && tcp.port=={flow['server_port']}"
    cmd = f"tshark -r {pcap_file} -Y \"{filter_exp}\" -T fields -e tcp.window_size | sort -n | tail -1"
    output = run_tshark(cmd)
    
    if output.strip():
        return int(output.strip())
    return 0

# Function to get throughput over time for a flow
def get_throughput_over_time(pcap_file, flow, interval=0.5):
    filter_exp = f"ip.addr=={flow['server_ip']} && ip.addr=={flow['client_ip']} && tcp.port=={flow['server_port']}"
    cmd = f"tshark -r {pcap_file} -q -z io,stat,{interval},\"{filter_exp}\""
    output = run_tshark(cmd)
    
    times = []
    throughputs = []
    started = False
    
    for line in output.strip().split('\n'):
        if "Interval" in line:
            started = True
            continue
            
        if not started or not line.strip() or '=' in line or '<>' in line:
            continue
            
        if '|' in line:
            parts = line.split('|')
            if len(parts) >= 2:
                time_range = parts[0].strip()
                if '-' in time_range:
                    try:
                        time_val = float(time_range.split('-')[0])
                        bytes_str = parts[1].strip()
                        
                        if bytes_str:
                            bytes_val = float(bytes_str)
                            mbps = (bytes_val * 8) / (interval * 1000000)
                            times.append(time_val)
                            throughputs.append(mbps)
                    except (ValueError, IndexError):
                        continue
    
    return times, throughputs

# Function to get window size over time for a flow
def get_window_size_over_time(pcap_file, flow):
    filter_exp = f"ip.addr=={flow['server_ip']} && ip.addr=={flow['client_ip']} && tcp.port=={flow['server_port']}"
    cmd = f"tshark -r {pcap_file} -Y \"{filter_exp}\" -T fields -e frame.time_epoch -e tcp.window_size"
    output = run_tshark(cmd)
    
    times = []
    window_sizes = []
    
    for line in output.strip().split('\n'):
        if not line.strip():
            continue
            
        parts = line.strip().split('\t')
        if len(parts) == 2:
            try:
                time_val = float(parts[0])
                window_size = int(parts[1])
                times.append(time_val)
                window_sizes.append(window_size)
            except (ValueError, IndexError):
                continue
    
    # Convert to relative time
    if times:
        start_time = min(times)
        times = [t - start_time for t in times]
    
    return times, window_sizes

# Function to attempt to identify the congestion algorithm
def identify_congestion_algorithm(pcap_file, exp_type, flow_index):
    # Fixed mapping for each experiment and flow
    algorithms = ["Reno", "Vegas", "H-TCP"]
    
    if exp_type == 'a':
        # For experiment A, we have a single client, but three separate tests with different algorithms
        if flow_index < len(algorithms):
            return algorithms[flow_index]
    elif exp_type == 'b':
        # For experiment B, we have three staggered clients, each test with a different algorithm
        if flow_index < len(algorithms):
            return algorithms[flow_index]
    elif exp_type == 'c' or exp_type == 'd':
        # For experiment C and D, we need to identify based on both flow order and test case
        # This is a simplification, you might need to adjust based on actual test organization
        return algorithms[flow_index % len(algorithms)]
    
    return f"Unknown Algorithm (Flow {flow_index+1})"

# Function to create visualizations based on metrics
def create_visualizations(pcap_file, exp_type, metrics, algorithms):
    print(f"\nGenerating visualizations for experiment {exp_type.upper()}...")
    
    # Throughput over time for all experiments
    plt.figure(figsize=(12, 6))
    for metric in metrics:
        flow = metric['flow']
        algorithm = metric['algorithm']
        
        times, throughputs = get_throughput_over_time(pcap_file, flow)
        
        if times and throughputs:
            avg_throughput = sum(throughputs) / len(throughputs) if throughputs else 0
            plt.plot(times, throughputs, label=f"{algorithm} (Avg: {avg_throughput:.2f} Mbps)")
    
    plt.xlabel('Time (seconds)')
    plt.ylabel('Throughput (Mbps)')
    plt.title(f'Throughput Over Time - Experiment {exp_type.upper()}')
    plt.legend()
    plt.grid(True)
    plt.savefig(f'throughput_over_time_exp_{exp_type}.png')
    plt.close()
    
    # Window size over time for all experiments
    plt.figure(figsize=(12, 6))
    for metric in metrics:
        flow = metric['flow']
        algorithm = metric['algorithm']
        
        times, window_sizes = get_window_size_over_time(pcap_file, flow)
        
        if times and window_sizes:
            max_win = max(window_sizes) if window_sizes else 0
            plt.plot(times, window_sizes, label=f"{algorithm} (Max: {max_win} bytes)")
    
    plt.xlabel('Time (seconds)')
    plt.ylabel('Window Size (bytes)')
    plt.title(f'TCP Window Size Over Time - Experiment {exp_type.upper()}')
    plt.legend()
    plt.grid(True)
    plt.savefig(f'window_size_over_time_exp_{exp_type}.png')
    plt.close()
    
    # If we have multiple algorithms to compare
    if algorithms:
        # Group metrics by algorithm
        algo_metrics = {}
        for algo in algorithms:
            algo_metrics[algo] = [m for m in metrics if m['algorithm'] == algo]
        
        # Prepare data for bar charts
        avg_throughputs = [sum(m['throughput'] for m in algo_metrics[algo])/len(algo_metrics[algo]) 
                           if algo_metrics[algo] else 0 for algo in algorithms]
        avg_goodputs = [sum(m['goodput'] for m in algo_metrics[algo])/len(algo_metrics[algo]) 
                        if algo_metrics[algo] else 0 for algo in algorithms]
        avg_loss_rates = [sum(m['loss_rate'] for m in algo_metrics[algo])/len(algo_metrics[algo]) 
                          if algo_metrics[algo] else 0 for algo in algorithms]
        max_windows = [max(m['max_window'] for m in algo_metrics[algo]) 
                       if algo_metrics[algo] else 0 for algo in algorithms]
        
        # Throughput comparison
        plt.figure(figsize=(10, 6))
        plt.bar(algorithms, avg_throughputs)
        plt.ylabel('Average Throughput (Mbps)')
        plt.title(f'Throughput Comparison - Experiment {exp_type.upper()}')
        plt.grid(axis='y')
        plt.savefig(f'throughput_comparison_exp_{exp_type}.png')
        plt.close()
        
        # Goodput comparison
        plt.figure(figsize=(10, 6))
        plt.bar(algorithms, avg_goodputs)
        plt.ylabel('Average Goodput (Mbps)')
        plt.title(f'Goodput Comparison - Experiment {exp_type.upper()}')
        plt.grid(axis='y')
        plt.savefig(f'goodput_comparison_exp_{exp_type}.png')
        plt.close()
        
        # Loss Rate comparison
        plt.figure(figsize=(10, 6))
        plt.bar(algorithms, avg_loss_rates)
        plt.ylabel('Average Loss Rate')
        plt.title(f'Loss Rate Comparison - Experiment {exp_type.upper()}')
        plt.grid(axis='y')
        plt.savefig(f'loss_comparison_exp_{exp_type}.png')
        plt.close()
        
        # Maximum Window Size comparison
        plt.figure(figsize=(10, 6))
        plt.bar(algorithms, max_windows)
        plt.ylabel('Maximum Window Size (bytes)')
        plt.title(f'Window Size Comparison - Experiment {exp_type.upper()}')
        plt.grid(axis='y')
        plt.savefig(f'window_size_comparison_exp_{exp_type}.png')
        plt.close()
        
        # Throughput vs Goodput (only for experiment A for backward compatibility)
        if exp_type == 'a':
            plt.figure(figsize=(12, 6))
            x = np.arange(len(algorithms))
            width = 0.35
            
            plt.bar(x - width/2, avg_throughputs, width, label='Throughput')
            plt.bar(x + width/2, avg_goodputs, width, label='Goodput')
            
            plt.xlabel('Algorithm')
            plt.ylabel('Rate (Mbps)')
            plt.title('Throughput vs Goodput Comparison')
            plt.xticks(x, algorithms)
            plt.legend()
            plt.grid(axis='y')
            plt.savefig('throughput_vs_goodput.png')
            plt.close()

# Process each PCAP file
results = {}

for pcap_file in pcap_files:
    print(f"\n{'='*50}")
    print(f"Analyzing {pcap_file}")
    print(f"{'='*50}")
    
    # Extract experiment type from filename
    exp_type = pcap_file.split('_')[1].split('.')[0]  # Should be 'a', 'b', 'c', or 'd'
    
    # Check if the file has iperf traffic
    if not check_for_iperf(pcap_file):
        print(f"No iperf traffic found in {pcap_file}")
        continue
    
    # Get all TCP flows
    flows = get_tcp_flows(pcap_file)
    
    if not flows:
        print(f"No TCP flows found in {pcap_file}")
        continue
    
    # Process each flow
    metrics = []
    for i, flow in enumerate(flows):
        print(f"\nProcessing flow {i+1}: {flow['flow']}")
        
        # Identify algorithm based on experiment type and flow index
        algorithm = identify_congestion_algorithm(pcap_file, exp_type, i)
        
        # Calculate flow duration
        duration = get_flow_duration(pcap_file, flow)
        print(f"  Flow duration: {duration:.2f} seconds")
        
        # Calculate metrics
        bytes_transferred = get_flow_bytes(pcap_file, flow)
        # Throughput in Mbps (bytes * 8 bits/byte / duration in seconds / 1,000,000 for Mbps)
        throughput = (bytes_transferred * 8) / (duration * 1000000) if duration > 0 else 0
        
        goodput_bytes = get_flow_goodput(pcap_file, flow)
        # Goodput in Mbps 
        goodput = (goodput_bytes * 8) / (duration * 1000000) if duration > 0 else 0
        
        loss_rate = get_flow_loss_rate(pcap_file, flow)
        max_window = get_max_window_size(pcap_file, flow)
        
        print(f"  Algorithm: {algorithm}")
        print(f"  Direction: {flow.get('direction', 'unknown')}")
        print(f"  Bytes: {bytes_transferred}, Goodput bytes: {goodput_bytes}")
        print(f"  Throughput: {throughput:.2f} Mbps, Goodput: {goodput:.2f} Mbps")
        print(f"  Loss rate: {loss_rate:.4f}, Max window: {max_window} bytes")
        
        metrics.append({
            'flow': flow,
            'algorithm': algorithm,
            'duration': duration,
            'bytes': bytes_transferred,
            'throughput': throughput,
            'goodput_bytes': goodput_bytes,
            'goodput': goodput,
            'loss_rate': loss_rate,
            'max_window': max_window
        })
    
    results[exp_type] = metrics
    
    # Create visualizations for each experiment
    algorithms = sorted(set([m['algorithm'] for m in metrics]))
    create_visualizations(pcap_file, exp_type, metrics, algorithms)

# Save results to CSV
data = []
for exp_type, metrics_list in results.items():
    for metric in metrics_list:
        data.append({
            'Experiment': exp_type,
            'Algorithm': metric['algorithm'],
            'Throughput (Mbps)': metric['throughput'],
            'Goodput (Mbps)': metric['goodput'],
            'Loss Rate': metric['loss_rate'],
            'Max Window Size (bytes)': metric['max_window']
        })
        
df = pd.DataFrame(data)
df.to_csv('tcp_congestion_results.csv', index=False)
print("\nResults saved to tcp_congestion_results.csv")

print("\nAnalysis complete. Check the PNG files for visualizations.")