# Mininet TCP Analysis

This project implements a Mininet topology with seven hosts (H1 to H7) connected to four switches (S1 to S4). The setup is designed to analyze TCP congestion control protocols using an iperf3 client-server configuration.

## Project Structure

- **src/**: Contains the source code for the custom topology, TCP server, TCP clients, and measurement scripts.
  - **custom_topo.py**: Defines the custom Mininet topology.
  - **tcp_server.py**: Implements the TCP server running on H7.
  - **tcp_client.py**: Implements the TCP clients running on H1 to H6.
  - **measurement/**: Contains scripts for measuring bandwidth and analyzing congestion.
    - **bandwidth.py**: Functions to measure bandwidth and throughput.
    - **congestion.py**: Functions to analyze congestion control protocols.
  
- **tests/**: Contains unit tests for the custom topology.
  - **test_topology.py**: Tests to ensure the Mininet setup is functioning correctly.

- **results/**: Contains scripts for processing and summarizing experimental results.
  - **metrics.py**: Processes throughput, goodput, packet loss, and window size metrics.

- **config.json**: Configuration settings for the project, including TCP parameters and link loss settings.

## Setup Instructions

1. Install Mininet and required dependencies.
2. Clone this repository.
3. Navigate to the project directory.
4. Run the custom topology using the command:
   ```
   sudo python src/custom_topo.py
   ```
5. Start the TCP server on H7:
   ```
   python src/tcp_server.py
   ```
6. Start the TCP clients on H1 to H6:
   ```
   python src/tcp_client.py
   ```

## Usage Examples

- To measure bandwidth, run:
  ```
  python src/measurement/bandwidth.py
  ```

- To analyze congestion control, run:
  ```
  python src/measurement/congestion.py
  ```

## Experiments Conducted

This project includes experiments to evaluate different TCP congestion control protocols under various network conditions. Results are summarized in the `results/metrics.py` file.