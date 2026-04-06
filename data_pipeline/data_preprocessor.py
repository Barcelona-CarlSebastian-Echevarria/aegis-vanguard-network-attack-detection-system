import pandas as pd
import numpy as np
import os
from app.config import *

def preprocess(converted_flows):
    
    df_converted_flows = pd.read_csv(converted_flows, encoding='latin-1')
    df_converted_flows = df_converted_flows.copy()

    # Drop unnecessary columns
    df_converted_flows = df_converted_flows.drop(columns=[
        "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "timestamp"
    ], errors="ignore")

    # Impute values in the dataset
    df_converted_flows = pd.DataFrame(np.nan_to_num(df_converted_flows, nan=0.0, posinf=0.0, neginf=0.0),
                    columns=df_converted_flows.columns,
                    index=df_converted_flows.index)
    
    # Detect inf and nan vals
    if np.any(np.isinf(df_converted_flows.values)) or np.any(np.isnan(df_converted_flows.values)):
        print("Warning: Data still contains inf or nan values")

    df_converted_flows.rename(columns=RENAME_MAP, inplace=True)
    
    return df_converted_flows