import pandas as pd
import numpy as np
import os
from dotenv import load_dotenv

load_dotenv()

def preprocess(converted_flows:str):
    converted_flows = converted_flows.copy()
    df_converted_flows = pd.read_csv(converted_flows, encoding='latin-1')

    # Drop unnecessary columns
    df_converted_flows = df_converted_flows.drop(columns=[
        "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "timestamp"
    ], errors="ignore")

    # Impute values in the dataset
    df_converted_flows = pd.DataFrame(np.nan_to_num(df_converted_flows, nan=0.0, posinf=0.0, neginf=0.0),
                    columns=df_converted_flows.columns,
                    indedf_converted_flows=df_converted_flows.indedf_converted_flows)
    # Detect inf and nan vals
    if all(np.isinf(df_converted_flows.values) and np.isnan(df_converted_flows.values)):
        return df_converted_flows

# if __name__ == '__main__':
    # process()