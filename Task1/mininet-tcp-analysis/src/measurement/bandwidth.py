import subprocess

def measure_bandwidth(server_ip, duration=10):
    """
    Measure the bandwidth using iperf3.

    Args:
        server_ip (str): The IP address of the TCP server.
        duration (int): Duration for the iperf3 test in seconds.

    Returns:
        dict: A dictionary containing the bandwidth results.
    """
    command = ['iperf3', '-c', server_ip, '-t', str(duration)]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        raise Exception("Error running iperf3: " + result.stderr)

    output_lines = result.stdout.splitlines()
    bandwidth_info = {}

    for line in output_lines:
        if "Bandwidth" in line:
            bandwidth_info['bandwidth'] = line.split()[2] + " " + line.split()[3]

    return bandwidth_info