# NSAnalyzer

![Python](https://img.shields.io/badge/Python-3.11-blue)  
![Flask](https://img.shields.io/badge/Flask-2.3.2-green)  
![Scapy](https://img.shields.io/badge/Scapy-2.5.0-orange)  
![License](https://img.shields.io/badge/License-MIT-yellow)

**NSAnalyzer**  is a network security tool designed to analyze network packets and detect potential attacks such as  **Port Scan**,  **SYN Flood**,  **DNS Flood**,  **UDP Flood**,  **ICMP Flood**, and  **ARP Flood**. It provides detailed insights into network activity, connected devices, and potential threats, making it an essential tool for network administrators and security professionals.

----------

## Features

-   **Network Device Listing**: List all devices connected to the network.
    
-   **Minimalistic Network Information**: Retrieve gateway, open ports, and MAC addresses.
    
-   **Packet Analysis**: Detect and report potential attacks with detailed information, including IP and MAC addresses.
    
-   **Attack Detection**: Identify and alert on attacks such as:
    
    -   Port Scan
        
    -   SYN Flood
        
    -   DNS Flood
        
    -   UDP Flood
        
    -   ICMP Flood
        
    -   ARP Flood
        
-   **Report Generation**: Generate JSON-based reports for analyzed packets and detected threats.
    

----------

## Technologies Used

-   **Backend**: Flask-based web server for handling network analysis requests.
    
-   **Packet Capture**:  `tcpdump`  for capturing network packets.
    
-   **Packet Analysis**:  `Scapy`  for handling and analyzing packet data.
    
-   **Storage & Security**: Reports stored in JSON format using Python's  `json`  library.
    

----------

## Installation

Follow these steps to set up  **NSAnalyzer**  using Conda:

1.  **Download and Install Conda**:
    
    -   Visit  [Miniconda Installation Page](https://docs.conda.io/en/latest/miniconda.html).
        
    -   Download the appropriate Miniconda installer for your OS.
        
    -   Follow the installation instructions on the website.
        
2.  **Verify Installation**:
```bash
conda --version
```  
    
3.  **Create a Conda Environment**:

```bash
conda create -n nsanalyzer python=3.11
```
    
3.  **Activate the Environment**:
    
```bash
conda activate nsanalyzer
```
    
4.  **Install Dependencies**:
       
```bash
pip install -r requirements.txt
```

5. **Be sure to create the .env file based on .env.example file**

6. **Must execute this in the terminal to let the tcpdump command to work without sudo** 

```
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```
6.  **Run the Flask App**:
    
```bash
python app.py
```
    

----------

## Usage

Once the Flask app is running, interact with  **NSAnalyzer**  through the web server hosted on  `localhost`. Open your browser and navigate to the provided localhost address (e.g.,  `http://127.0.0.1:FLASK_PORT`).
The FLASK_PORT env key has as default value "4000".
### Key Functionalities:

-   **List Connected Devices**: View all devices connected to the network.
    
-   **Network Information**: Retrieve gateway, open ports, and MAC addresses.
    
-   **Packet Analysis**: Analyze network packets and detect potential attacks.
    
-   **Reports**: Access JSON-based reports for detailed insights.
    
----------

## Demo
A live demo of NSAnalyzer is available for testing. To access the demo, use the following credentials:

- Username: user
- Password: user

> **Important Note:** 
> This user is created only for demonstration purposes. It is not a best practice to include credentials directly in the README file in a real-world project. 
>In production, credentials should be stored securely using environment variables or a secrets management tool.