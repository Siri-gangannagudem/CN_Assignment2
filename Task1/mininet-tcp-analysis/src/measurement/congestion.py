import subprocess
import os

def capture_traffic(interface, duration, output_file):
    """Capture traffic using tshark"""
    cmd = f"tshark -i {interface} -w {output_file} -a duration:{duration}"
    subprocess.Popen(cmd.split())

def analyze_pcap(pcap_file):
    """Analyze captured traffic for metrics using tshark"""
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} does not exist")
        return None
    
    # Get packet count
    cmd = f"tshark -r {pcap_file} | wc -l"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    packet_count = int(result.stdout.strip())
    
    return {"packet_count": packet_count}

def measure_goodput(pcap_file):
    """Calculate goodput from pcap file"""
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} does not exist")
        return 0
    
    # Get total bytes
    cmd = f"tshark -r {pcap_file} -T fields -e frame.len | awk '{{sum += $1}} END {{print sum}}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if not result.stdout.strip():
        return 0
    
    total_bytes = int(result.stdout.strip())
    
    # Get duration
    cmd_start = f"tshark -r {pcap_file} -T fields -e frame.time_epoch -c 1"
    cmd_end = f"tshark -r {pcap_file} -T fields -e frame.time_epoch | tail -n 1"
    
    result_start = subprocess.run(cmd_start, shell=True, capture_output=True, text=True)
    result_end = subprocess.run(cmd_end, shell=True, capture_output=True, text=True)
    
    if not result_start.stdout.strip() or not result_end.stdout.strip():
        return 0
    
    start_time = float(result_start.stdout.strip())
    end_time = float(result_end.stdout.strip())
    duration = end_time - start_time
    
    if duration == 0:
        return 0
    
    goodput = total_bytes * 8 / duration  # bits per second
    return goodput

def measure_packet_loss(pcap_file):
    """Calculate packet loss rate"""
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} does not exist")
        return 0
    
    # Count total packets
    cmd_total = f"tshark -r {pcap_file} | wc -l"
    result_total = subprocess.run(cmd_total, shell=True, capture_output=True, text=True)
    
    if not result_total.stdout.strip():
        return 0
    
    total_packets = int(result_total.stdout.strip())
    
    # Count retransmissions
    cmd_retrans = f"tshark -r {pcap_file} -Y 'tcp.analysis.retransmission' | wc -l"
    result_retrans = subprocess.run(cmd_retrans, shell=True, capture_output=True, text=True)
    
    if not result_retrans.stdout.strip():
        lost_packets = 0
    else:
        lost_packets = int(result_retrans.stdout.strip())
    
    if total_packets == 0:
        return 0
    
    packet_loss_rate = lost_packets / total_packets
    return packet_loss_rate

def measure_window_size(pcap_file):
    """Track TCP window size over time"""
    if not os.path.exists(pcap_file):
        print(f"Error: {pcap_file} does not exist")
        return []
    
    # Get window sizes
    cmd = f"tshark -r {pcap_file} -T fields -e tcp.window_size"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    window_sizes = []
    for line in result.stdout.strip().split('\n'):
        if line:
            try:
                window_sizes.append(int(line))
            except ValueError:
                pass
    
    return window_sizes