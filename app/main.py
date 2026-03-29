import pandas as pd
import numpy as np
from config import ROOT, DATASET_FILE
import joblib
import subprocess

def binary_layer(X):
    '''
    Classifies the behaviour of traffic if
    BENIGN - Normal
    ATTCK - Threat detected
    '''

    X = X.copy()
    pred = binary_model.predict(X)
    print(pred)

    if len(pred) == 1:
        if pred[0] == 0:
            return "BENIGN"
        return "ATTACK"

# 
def attack_layer(X):
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
    pred = int(*pred)

    return attack_map[pred]

def capture(interface="Wi-Fi"):
        subprocess.run([
        "dumpcap",
        "-i", interface,           
        "-a", "duration:5",
        "-w", "traffic.pcap"
    ])


def main(data):

    network_status = binary_layer(data)

    if network_status == "BENIGN":
        print("BENIGN")
        return

    attack_type = attack_layer(data)
    print(attack_type)
    return


if __name__ == '__main__':

    binary_model = joblib.load(f"{ROOT}/models/layer1_xgb_pipeline.pkl")
    attack_model = joblib.load(f"{ROOT}/models/layer2_rf_smote_pipeline.pkl")

    main_data = pd.read_csv(DATASET_FILE)
    def preprocessing(main_data):
        # -- For Heartbleed attack (lowest count in the dataset) --
        main_data = main_data.loc[main_data["Label"] == "Heartbleed", :]
        X = main_data.drop(columns="Label")

        # -- Detect and impute missing and inf datas --
        X = pd.DataFrame(np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0),
                        columns=X.columns,
                        index=X.index)
        # Detect inf and nan vals
        print(np.isinf(X.values).any())
        print(np.isnan(X.values).any()) 
    
    # -- Static test --
    data_sample = X.sample(1)
    main(data_sample)