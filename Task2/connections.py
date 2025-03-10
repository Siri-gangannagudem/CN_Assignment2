import matplotlib.pyplot as plt

connections = {}

with open('connections1.txt', 'r') as file:
    for line in file:
        fields = line.strip().split()
        if len(fields) < 8:
            continue
        src_ip, dst_ip, src_port, dst_port, time_relative, syn, ack, fin, rst = fields
        key = (src_ip, dst_ip, src_port, dst_port)
        time_relative = float(time_relative)
        syn, ack, fin, rst = int(syn), int(ack), int(fin), int(rst)

        if key not in connections:
            connections[key] = {'start': time_relative, 'end': None, 'duration': None}

        if rst == 1 or (fin == 1 and ack == 1):
            connections[key]['end'] = time_relative
            connections[key]['duration'] = time_relative - connections[key]['start']

# Assign default duration of 100 seconds for incomplete connections
for key, value in connections.items():
    if value['duration'] is None:
        value['duration'] = 100

# Plot the connection duration vs. connection start time
start_times = [value['start'] for value in connections.values()]
durations = [value['duration'] for value in connections.values()]

plt.figure(figsize=(10, 6))
plt.scatter(start_times, durations, label='Connection Duration')
plt.axvline(x=20, color='r', linestyle='--', label='Attack Start')
plt.axvline(x=120, color='g', linestyle='--', label='Attack End')
plt.xlabel('Connection Start Time (s)')
plt.ylabel('Connection Duration (s)')
plt.title('Connection Duration vs. Connection Start Time')
plt.legend()
plt.grid(True)
plt.savefig('connection_duration_plot.png')
plt.show()