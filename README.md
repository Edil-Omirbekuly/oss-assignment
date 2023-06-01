# Network Scanner and Traffic Analysis

This script allows you to scan a network for open ports and perform traffic analysis on a specific IP address. It uses the `nmap` library for network scanning, the `scapy` library for packet sniffing and `requests` library for password cracking.

## Prerequisites

- nmap library (`pip install python-nmap`)
- scapy library (`pip install scapy`)
- requests library (`pip install requests`)

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/network-scanner.git
   
 2. Run the script:
    ```bash
    python script.py
    
 3. Follow the prompts to enter the IP address for scanning and the network interface for traffic analysis.

 4. The script will perform a network scan and display open ports on the target host. Then, it will start capturing network packets on the specified interface.

 5. Once the packet capture is complete, the script will display statistics and a report of the captured packets.

 6. If you want to perform a password cracking attack, enter the required information when prompted (URL, username, passwords file, and error message). The script will try each password   from the file until a successful login is found or the list is exhausted.

Note: Please use this script responsibly and only on networks/systems you have permission to scan/test.

## Screenshots

<a href="https://imgbb.com/"><img src="https://i.ibb.co/mRRj4PN/image-2023-06-02-03-04-57.png" alt="image-2023-06-02-03-04-57" border="0"></a>
<a href="https://imgbb.com/"><img src="https://i.ibb.co/Mg3rBhS/image-2023-06-02-03-05-26.png" alt="image-2023-06-02-03-05-26" border="0"></a>
<a href="https://imgbb.com/"><img src="https://i.ibb.co/5v0tt0Q/image-2023-06-02-03-04-26.png" alt="image-2023-06-02-03-04-26" border="0"></a>

## License

This project is licensed under the MIT License.

