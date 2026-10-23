import pandas as pd
import os

columns = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt",
    "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label"
]

def combine_and_split():
    print("Reading all 4 CSV files...")
    df1 = pd.read_csv("../datasets/UNSW-NB15_1.csv", header=None, names=columns, low_memory=False)
    df2 = pd.read_csv("../datasets/UNSW-NB15_2.csv", header=None, names=columns, low_memory=False)
    df3 = pd.read_csv("../datasets/UNSW-NB15_3.csv", header=None, names=columns, low_memory=False)
    df4 = pd.read_csv("../datasets/UNSW-NB15_4.csv", header=None, names=columns, low_memory=False)

    print("Combining all files...")
    df = pd.concat([df1, df2, df3, df4], ignore_index=True)

    # Data ko shuffle karein taake mix ho jaye
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # 80% Training, 20% Testing
    split_index = int(len(df) * 0.8)
    train_df = df.iloc[:split_index]
    test_df = df.iloc[split_index:]

    train_df.to_csv("../datasets/train_data.csv", index=False)
    test_df.to_csv("../datasets/test_data.csv", index=False)
    
    print(f"✅ Success! Training records: {len(train_df)}, Testing records: {len(test_df)}")
    print("Saved as 'train_data.csv' and 'test_data.csv' in datasets folder.")

if __name__ == "__main__":
    combine_and_split()