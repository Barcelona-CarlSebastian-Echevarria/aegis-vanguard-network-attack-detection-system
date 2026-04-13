import pandas as pd
import numpy as np
import joblib
import subprocess
import os
import shutil

from app.config import *
from data_pipeline.packet_capture import *

from dotenv import load_dotenv
load_dotenv()

def binary_layer(X, binary_model):
    '''
    Classifies the behaviour of traffic if
    BENIGN - Normal
    ATTCK - Threat detected
    '''

    X = X.copy()
    pred = binary_model.predict(X)

    if len(pred) == 1:
        if pred[0] == 0:
            return "BENIGN"
        return "ATTACK"

# 
def attack_layer(X, attack_model):
    '''
    Classifies the type of attack detected according to the encoded map from training
    '''

    attack_map = {
        0: 'Bot',
        1: 'DDoS',
        2: 'DoS GoldenEye',
        3: 'DoS Hulk',
        4: 'DoS Slowhttptest',
        5: 'DoS slowloris',
        6: 'FTP-Patator',
        7: 'Heartbleed',
        8: 'Infiltration',
        9: 'PortScan',
        10: 'SSH-Patator',
        11: 'Web Attack'
    }

    X = X.copy()

    pred = attack_model.predict(X)
    return attack_map[pred]

def predict(df, binary_model, attack_model):
    ''' 
    Predict the incoming flows 
    '''

    for i in range(len(df)):
        row = df.iloc[[i]]
        network_status = binary_layer(row, binary_model)
        
        if network_status == "BENIGN":
            print(f"[{i}] BENIGN")
            continue
            
        attack_type = attack_layer(row, attack_model)
        print(f"[{i}] ATTACK: {attack_type}")

def main(binary_model, attack_model): 
    '''
    Scan incoming folder, process new flow CSVs, then move to scanned folder
    '''

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(SCANNED_DIR, exist_ok=True)
    # Sort directories 
    files = sorted(os.listdir(OUTPUT_DIR))  

    for file in files:
        if not file.startswith("flow") or not file.endswith(".csv"):
            continue
        # Stage the file
        file_path = os.path.join(OUTPUT_DIR, file)

        # Load CSV, then feed to model
        try:
            print(f"Processing: {file}")
            df = pd.read_csv(file_path)

            if not df.empty:
                predict(df, binary_model, attack_model) 

            # After the file is scanned, it will be moved to converted_flows/scanned
            destination = os.path.join(SCANNED_DIR, file)
            shutil.move(file_path, destination)
            print(f"Moved to scanned: {file}")

        except Exception as e:
            print(f"Error processing {file}: {e}")

if __name__ == '__main__':

    binary_model = joblib.load(BINARY_MODEL)
    attack_model = joblib.load(CLASSIFIER_MODEL)
    
    pcap_file = capture(capture_seconds=5, interface="eth0")
    if not os.path.exists(pcap_file):
        print("PCAP not found:", pcap_file)
    print("PCAP created:", pcap_file)

    csv_path, df = convert_packets(pcap_file)
    if not os.path.exists(csv_path):
        print("CSV not found:", csv_path)
    print("CSV created:", csv_path)
    
    # Feed to the model
    main(binary_model, attack_model)

