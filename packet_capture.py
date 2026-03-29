import subprocess
import os
from pathlib import Path

def capture(interface="Wi-Fi"):
    ROOT_DIR = Path.cwd()
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

capture()