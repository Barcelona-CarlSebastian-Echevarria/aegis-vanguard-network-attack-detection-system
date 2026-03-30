import subprocess
import os
from pathlib import Path
from datetime import date

ROOT_DIR = Path.cwd()
pcap_path = os.path.join(ROOT_DIR, "packets_captured", "traffic1.pcap")

def capture(interface="Wi-Fi"):
    target_dir = os.path.join(ROOT_DIR, "packets_captured")
    
    # Create the directory if it doesn't exist
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    # Output file construction
    output_file = os.path.join(target_dir, "traffic1.pcap")

    subprocess.run([
        "dumpcap",
        "-i", interface,           
        "-a", "duration:5",
        "-w", output_file
    ])

def convert_packets(pcap_path, output_name: str):
    if not isinstance(output_name, str):
        raise ValueError("outname not string") 

    csv_directory = os.path.join(ROOT_DIR, "converted_flows")

    if not os.path.exists(csv_directory):
        os.makedirs(csv_directory)

    output_path = os.path.join(csv_directory, output_name)
    
    subprocess.run([
        "cicflowmeter",
        "-f", str(pcap_path),
        "-c", f"{output_path}.csv"
    ], check=True)

    return f"{output_path}.csv"  


if __name__ == '__main__':
    # capture()
    csv_file = convert_packets(pcap_path, 'flow_output')
    if not os.path.exists(csv_file):
        print(csv_file, "not found in directory")
    print(csv_file, "successfully create")