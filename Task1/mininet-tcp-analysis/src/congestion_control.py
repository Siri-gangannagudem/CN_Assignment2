import sys
import os
import subprocess
import traceback

# Add the virtual environment's site-packages to PYTHONPATH
venv_site_packages = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'cn', 'lib', 'python3.12', 'site-packages')
sys.path.append(venv_site_packages)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import time
from mininet.net import Mininet
from mininet.node import Node, OVSController
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.clean import cleanup
from src.tcp_server import start_iperf_server
from src.tcp_client import start_iperf_client, run_staggered_test

def run_experiment_a(net):
    """Run experiment a: Single client H1 to server H7"""
    print("Running experiment A")
    h1, h7 = net.get('h1', 'h7')
    server = start_iperf_server()
    
    congestion_schemes = ['reno', 'vegas', 'htcp']
    for cc in congestion_schemes:
        print(f"Testing congestion control: {cc}")
        start_iperf_client(h1.IP(), h7.IP(), congestion=cc)
    
    server.terminate()

def run_experiment_b(net):
    """Run experiment B: Staggered clients H1, H3, H4 to server H7"""
    print("Running experiment B")
    h1, h3, h4, h7 = net.get('h1', 'h3', 'h4', 'h7')
    server = start_iperf_server()
    
    congestion_schemes = ['reno', 'vegas', 'htcp']
    for cc in congestion_schemes:
        print(f"Testing congestion control: {cc}")
        run_staggered_test(h7.IP(), congestion_scheme=cc)
    
    server.terminate()

def run_experiment_c(net):
    """Run experiment C: Different bandwidth configurations"""
    print("Running experiment C")
    h1, h2, h3, h4, h7 = net.get('h1', 'h2', 'h3', 'h4', 'h7')
    server = start_iperf_server()
    
    # Test 1: H3 to H7
    print("Testing H3 to H7")
    start_iperf_client(h3.IP(), h7.IP(), congestion='reno')
    
    # Test 2a: H1 and H2 to H7
    print("Testing H1 and H2 to H7")
    start_iperf_client(h1.IP(), h7.IP(), congestion='reno')
    start_iperf_client(h2.IP(), h7.IP(), congestion='reno')
    
    # Test 2b: H1 and H3 to H7
    print("Testing H1 and H3 to H7")
    start_iperf_client(h1.IP(), h7.IP(), congestion='reno')
    start_iperf_client(h3.IP(), h7.IP(), congestion='reno')
    
    # Test 2c: H1, H3, and H4 to H7
    print("Testing H1, H3, and H4 to H7")
    start_iperf_client(h1.IP(), h7.IP(), congestion='reno')
    start_iperf_client(h3.IP(), h7.IP(), congestion='reno')
    start_iperf_client(h4.IP(), h7.IP(), congestion='reno')
    
    server.terminate()

def run_experiment_d(net):
    """Run experiment D: Configure link loss and repeat experiment C"""
    print("Running experiment D")
    s2, s3 = net.get('s2', 's3')
    link = net.linksBetween(s2, s3)[0]
    
    for loss in [1, 5]:
        print(f"Configuring link loss to {loss}%")
        link.intf1.config(loss=loss)
        run_experiment_c(net)

def clean_mininet():
    """Clean up Mininet environment"""
    print("Cleaning up Mininet...")
    cleanup()
    # For more thorough cleanup, you can also run these commands
    subprocess.run(["sudo", "mn", "-c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--option', choices=['a', 'b', 'c', 'd'], required=True)
    args = parser.parse_args()

    setLogLevel('info')
    
    # Clean up Mininet before starting
    clean_mininet()
    
    # Start capturing traffic with tcpdump in background
    pcap_file = f'experiment_{args.option}.pcap'
    print(f"Starting traffic capture to {pcap_file}...")
    
    # Use -s 65535 to capture full packets, -Z to change privilege after opening
    tcpdump_process = subprocess.Popen(['sudo', 'tcpdump', '-i', 'any', '-s', '65535', 
                                        '-w', pcap_file, '-Z', os.getenv('USER')], 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Wait a moment to ensure tcpdump is running
    time.sleep(2)
    
    # Create a simple network manually without using a topology
    # Use OVSController which is usually installed with Mininet
    net = Mininet(
        controller=OVSController,  # Use OVSController instead of Controller
        link=TCLink
    )
    
    # Add controller
    net.addController('c0')
    
    # Add hosts
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    h5 = net.addHost('h5')
    h6 = net.addHost('h6')
    h7 = net.addHost('h7')
    
    # Add switches
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')
    
    # Add links
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(h5, s3)
    net.addLink(h6, s3)
    net.addLink(h7, s4)
    
    # Connect switches
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s4)
    
    # Configure the network based on the option
    if args.option == 'c':
        # Configure links with specific bandwidths for option c
        net.linksBetween(s1, s2)[0].intf1.config(bw=100)
        net.linksBetween(s2, s3)[0].intf1.config(bw=50)
        net.linksBetween(s3, s4)[0].intf1.config(bw=100)
    
    try:
        net.start()

        # Run the appropriate experiment
        if args.option == 'a':
            run_experiment_a(net)
        elif args.option == 'b':
            run_experiment_b(net)
        elif args.option == 'c':
            run_experiment_c(net)
        elif args.option == 'd':
            run_experiment_d(net)
        
        # Allow some time for traffic to complete
        print("Experiment completed. Waiting for traffic to finish...")
        time.sleep(5)
        
    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()
    
    finally:
        print("Stopping network...")
        if 'net' in locals():
            net.stop()
            
        # Stop tcpdump capture properly
        if 'tcpdump_process' in locals():
            print("Stopping traffic capture...")
            # Send SIGTERM signal for graceful shutdown
            tcpdump_process.terminate()
            # Wait for it to complete
            try:
                tcpdump_process.wait(timeout=5)
                print(f"Traffic capture saved to {pcap_file}")
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't terminate in time
                tcpdump_process.kill()
                print("Had to forcefully terminate tcpdump")
        
        # Make sure file permissions are correct
        if os.path.exists(pcap_file):
            subprocess.run(['sudo', 'chmod', '644', pcap_file])
            print(f"Permissions updated for {pcap_file}")
        
        # Analyze the pcap file
        print("Analyzing captured traffic...")
        subprocess.run(['sudo', 'chown', os.getenv('USER'), pcap_file])
        print(f"To view the capture, run: wireshark {pcap_file}")
        
        # Clean up again after stopping
        clean_mininet()

if __name__ == '__main__':
    main()