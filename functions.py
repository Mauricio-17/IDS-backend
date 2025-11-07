from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import redis
import json
import pandas as pd
import datetime

PROTO_MAP = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "GRE": 47,
    "ESP": 50,
    "ICMPV6": 58,
    "SCTP": 132
}

class Parser:
    def __init__(self):
        self.logs = None
        self.group = None
    
    def retrieve_logs(self, amount):
        r = redis.StrictRedis(host='localhost', port=6379, db=0)
    
        data = r.lrange("suricata", 0, amount)
        data = [json.loads(i) for i in data]
        filtered = [i for i in data if i["event_type"] not in ["stats", "fileinfo"]]
        frame = pd.json_normalize(filtered)
        self.group = frame.groupby("flow_id")
        
        if filtered is not None:
            return filtered
        else:
            return None

    def process(self):
        self.logs = self.retrieve_logs(600)
        filtered = self.group.filter(lambda g: (g["event_type"].isin(["flow", "alert"])).any())
        
        self.group = filtered.groupby("flow_id")
        flows_id = [flow_id for flow_id, data in self.group]

        filtered_logs = [log for log in self.logs if (log["flow_id"] in flows_id)]
        filtered_logs = sorted(filtered_logs, key=lambda x: x["timestamp"])
        data = {}

        for log in filtered_logs:
            timestamp = log.get("timestamp")
            fid = log.get("flow_id")
            src_port = log.get("src_port")
            dst_port = log.get("dest_port")
            proto = log.get("proto", "").upper()

            src_ip = log.get("src_ip")
            dst_ip = log.get("dest_ip")
            bytes_toserver = log.get("flow", {}).get("bytes_toserver", 0)
            bytes_toclient = log.get("flow", {}).get("bytes_toclient", 0)
            pkts_toserver = log.get("flow", {}).get("pkts_toserver", 0)
            pkts_toclient = log.get("flow", {}).get("pkts_toclient", 0)
            start = log.get("flow", {}).get("start")
            end = log.get("flow", {}).get("end")
            duration = log.get("flow", {}).get("age", 0)

            # Compute duration if not provided
            if duration == 0 and start and end:
                try:
                    t1 = datetime.datetime.strptime(start[:26], "%Y-%m-%dT%H:%M:%S.%f")
                    t2 = datetime.datetime.strptime(end[:26], "%Y-%m-%dT%H:%M:%S.%f")
                    duration = (t2 - t1).total_seconds()
                except Exception:
                    duration = 0

            total_bytes = bytes_toserver + bytes_toclient
            total_pkts = pkts_toserver + pkts_toclient

            # Derived fields
            flow_byts_s = total_bytes / duration if duration > 0 else 0
            flow_pkts_s = total_pkts / duration if duration > 0 else 0
            down_up_ratio = (bytes_toclient / bytes_toserver) if bytes_toserver > 0 else 0
            avg_pkt_size = (total_bytes / total_pkts) if total_pkts > 0 else 0
            avg_fwd_seg_size = (bytes_toserver / pkts_toserver) if pkts_toserver > 0 else 0
            avg_bwd_seg_size = (bytes_toclient / pkts_toclient) if pkts_toclient > 0 else 0
            fwd_packets_s = pkts_toserver / duration if duration > 0 else 0
            bwd_packets_s = pkts_toclient / duration if duration > 0 else 0
            fin_flag_count = 1 if log.get("tcp", {}).get("fin", False) else 0
            syn_flag_count = 1 if log.get("tcp", {}).get("syn", False) else 0
            rst_flag_count = 1 if log.get("tcp", {}).get("rst", False) else 0
            psh_flag_count = 1 if log.get("tcp", {}).get("psh", False) else 0
            ack_flag_count = 1 if log.get("tcp", {}).get("ack", False) else 0
            
            if fid not in data:
                data[fid] = {
                    "timestamp": timestamp,
                    "Flow id": fid,
                    "src ip": src_ip,
                    "dst ip": dst_ip,
                    "Src Port": src_port,
                    "Dst Port": dst_port,
                    "Protocol": PROTO_MAP.get(proto, 0),
                    "Flow Duration": duration,
                    "Total Fwd Packet": pkts_toserver,
                    "Total Bwd packets": pkts_toclient,
                    "Total Length of Fwd Packet": bytes_toserver,
                    "Total Length of Bwd Packet": bytes_toclient,
                    "Flow Bytes/s": round(flow_byts_s, 2),
                    "Flow Packets/s": round(flow_pkts_s, 2),
                    "Down/Up Ratio": round(down_up_ratio, 2),
                    "Average Packet Size": round(avg_pkt_size, 2),
                    "Fwd Segment Size Avg": round(avg_fwd_seg_size, 2),
                    "Bwd Segment Size Avg": round(avg_bwd_seg_size, 2),
                    "Fwd Packets/s": round(fwd_packets_s, 2),
                    "Bwd Packets/s": round(bwd_packets_s, 2),

                    "Fwd PSH Flags": psh_flag_count,
                    "Bwd PSH Flags": 0,
                    "Fwd RST Flags": rst_flag_count,
                    "Bwd RST Flags": 0,

                    "FIN Flag Count": fin_flag_count,
                    "SYN Flag Count": syn_flag_count,
                    "RST Flag Count": rst_flag_count,
                    "PSH Flag Count": psh_flag_count,
                    "ACK Flag Count": ack_flag_count,

                    "Fwd packet count": 1,
                    "Fwd sum bytes": bytes_toserver,
                    "Fwd sum packets": pkts_toserver,
                    "Fwd sum duration": duration,
                    "Fwd Bytes/Bulk Avg": pkts_toserver,
                    "Bwd packet count": 1,
                    "Bwd sum bytes": bytes_toclient,
                    "Bwd sum packets": pkts_toclient,
                    "Bwd sum duration": duration,
                    "Bwd Bytes/Bulk Avg": pkts_toclient,

                    "Fwd Packet/Bulk Avg": pkts_toserver,
                    "Fwd Bulk Rate Avg": round(1 / int(duration), 2) if int(duration) != 0 else 0,
                    "Bwd Packet/Bulk Avg": pkts_toclient,
                    "Bwd Bulk Rate Avg": round(1 / int(duration), 2) if int(duration) != 0 else 0,
                }
            else: # For the second and further related connection
                
                data[fid]["Fwd Segment Size Avg"] = round(data[fid]["Fwd Segment Size Avg"] + avg_fwd_seg_size, 2)
                data[fid]["Bwd Segment Size Avg"] = round(data[fid]["Bwd Segment Size Avg"] + avg_bwd_seg_size, 2)
                data[fid]["Average Packet Size"] = round(data[fid]["Average Packet Size"] + avg_pkt_size, 2)
                data[fid]["Down/Up Ratio"] = round(data[fid]["Down/Up Ratio"] + down_up_ratio, 2)
                data[fid]["Flow Bytes/s"] = round(data[fid]["Flow Bytes/s"] + flow_byts_s, 2)
                data[fid]["Flow Packets/s"] = round(data[fid]["Flow Packets/s"] + flow_pkts_s, 2)
                data[fid]["FIN Flag Count"] = data[fid]["FIN Flag Count"] + fin_flag_count
                data[fid]["SYN Flag Count"] = data[fid]["SYN Flag Count"] + syn_flag_count
                data[fid]["RST Flag Count"] = data[fid]["RST Flag Count"] + rst_flag_count
                data[fid]["PSH Flag Count"] = data[fid]["PSH Flag Count"] + psh_flag_count
                data[fid]["ACK Flag Count"] = data[fid]["ACK Flag Count"] + ack_flag_count

                t1 = datetime.datetime.strptime(data[fid]["timestamp"][:26], "%Y-%m-%dT%H:%M:%S.%f")
                t2 = datetime.datetime.strptime(timestamp[:26], "%Y-%m-%dT%H:%M:%S.%f")
                duration = (t2 - t1).total_seconds()
                data[fid]["Flow Duration"] = data[fid]["Flow Duration"] + duration
                
                if data[fid]["src ip"] == src_ip:

                    data[fid]["Fwd Packets/s"] = round(data[fid]["Fwd Packets/s"] + fwd_packets_s, 2)
                    data[fid]["Bwd Packets/s"] = round(data[fid]["Bwd Packets/s"] + bwd_packets_s, 2)
                    
                    data[fid]["Total Fwd Packet"] = data[fid]["Total Fwd Packet"] + pkts_toserver
                    data[fid]["Total Bwd packets"] = data[fid]["Total Bwd packets"] + pkts_toclient

                    # Sum of bulks
                    data[fid]["Fwd packet count"] = data[fid]["Fwd packet count"] + 1

                    data[fid]["Fwd sum duration"] = data[fid]["Fwd sum duration"] + duration

                    data[fid]["Total Length of Fwd Packet"] = data[fid]["Total Length of Fwd Packet"] + bytes_toserver
                    data[fid]["Total Length of Bwd Packet"] = data[fid]["Total Length of Bwd Packet"] + bytes_toclient
                    
                    data[fid]["Fwd sum packets"] = data[fid]["Fwd sum packets"] + pkts_toserver
                    data[fid]["Bwd sum packets"] = data[fid]["Bwd sum packets"] + pkts_toclient
                    
                    data[fid]["Fwd sum bytes"] = data[fid]["Fwd sum bytes"] + bytes_toserver
                    data[fid]["Bwd sum bytes"] = data[fid]["Bwd sum bytes"] + bytes_toclient

                    data[fid]["Fwd PSH Flags"] = data[fid]["Fwd PSH Flags"] + psh_flag_count
                    data[fid]["Fwd RST Flags"] = data[fid]["Fwd RST Flags"] + rst_flag_count
                    
                else:

                    data[fid]["Fwd Packets/s"] = round(data[fid]["Fwd Packets/s"] + bwd_packets_s, 2)
                    data[fid]["Bwd Packets/s"] = round(data[fid]["Bwd Packets/s"] + fwd_packets_s, 2)

                    data[fid]["Total Fwd Packet"] = data[fid]["Total Fwd Packet"] + pkts_toclient
                    data[fid]["Total Bwd packets"] = data[fid]["Total Bwd packets"] + pkts_toserver
                    
                    # Sum of bulks
                    data[fid]["Bwd packet count"] = data[fid]["Bwd packet count"] + 1

                    data[fid]["Bwd sum duration"] = data[fid]["Bwd sum duration"] + duration

                    data[fid]["Total Length of Fwd Packet"] = data[fid]["Total Length of Fwd Packet"] + bytes_toclient
                    data[fid]["Total Length of Bwd Packet"] = data[fid]["Total Length of Bwd Packet"] + bytes_toserver

                    data[fid]["Bwd sum packets"] = data[fid]["Bwd sum packets"] + pkts_toserver
                    data[fid]["Fwd sum packets"] = data[fid]["Fwd sum packets"] + pkts_toclient
                    
                    data[fid]["Bwd sum bytes"] = data[fid]["Bwd sum bytes"] + bytes_toserver
                    data[fid]["Fwd sum bytes"] = data[fid]["Fwd sum bytes"] + bytes_toclient

                    data[fid]["Bwd PSH Flags"] = data[fid]["Bwd PSH Flags"] + psh_flag_count
                    data[fid]["Bwd RST Flags"] = data[fid]["Bwd RST Flags"] + rst_flag_count

                data[fid]["timestamp"] = timestamp
                data[fid]["Fwd Bytes/Bulk Avg"] = data[fid]["Fwd sum bytes"] / data[fid]["Fwd packet count"]
                data[fid]["Bwd Bytes/Bulk Avg"] = data[fid]["Bwd sum bytes"] / data[fid]["Bwd packet count"]
                    
                data[fid]["Fwd Packet/Bulk Avg"] = data[fid]["Fwd sum packets"] + data[fid]["Fwd packet count"]
                data[fid]["Bwd Packet/Bulk Avg"] = data[fid]["Bwd sum packets"] + data[fid]["Bwd packet count"]
                    
                data[fid]["Fwd Bulk Rate Avg"] = round(data[fid]["Fwd packet count"] / int(data[fid]["Fwd sum duration"]), 2) if int(data[fid]["Fwd sum duration"]) > 0 else 0
                data[fid]["Bwd Bulk Rate Avg"] = round(data[fid]["Bwd packet count"] / int(data[fid]["Bwd sum duration"]), 2) if int(data[fid]["Bwd sum duration"]) > 0 else 0
        
        new_logs = [data[i] for i in flows_id]
        
        new_df = pd.json_normalize(new_logs)
        
        df_display = new_df[['timestamp', "Flow id", "src ip", "dst ip", 'Src Port', 'Dst Port', 'Protocol', 'Flow Duration', 'Total Length of Fwd Packet', 'Total Length of Bwd Packet']]
        
        flows_id = new_df["Flow id"]
        new_df = new_df[['Src Port', 'Dst Port', 'Protocol',
       'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
       'Total Length of Fwd Packet', 'Total Length of Bwd Packet',
       'Flow Bytes/s', 'Flow Packets/s', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd RST Flags',
       'Bwd RST Flags',
       'Fwd Packets/s', 'Bwd Packets/s', 'FIN Flag Count', 'SYN Flag Count',
       'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg',
       'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg',
       'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg']]
        
        
        df_inject = pd.read_csv("inject.csv")
        df_inject = df_inject[['Src Port', 'Dst Port', 'Protocol',
       'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
       'Total Length of Fwd Packet', 'Total Length of Bwd Packet',
       'Flow Bytes/s', 'Flow Packets/s', 'Fwd PSH Flags',
       'Bwd PSH Flags', 'Fwd RST Flags',
       'Bwd RST Flags',
       'Fwd Packets/s', 'Bwd Packets/s', 'FIN Flag Count', 'SYN Flag Count',
       'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg',
       'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg',
       'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg']]
        
        
        new_df["Protocol"] = new_df["Protocol"].map({
            0: "OTHER",
            6: "TCP",
            17: "UDP",
            1: "ICMP"
        })
        new_df["Protocol"].value_counts()
        
        final_df = pd.concat([df_inject, new_df], axis=0)
        final_df.isna().sum()
        
        ## Encoding and scaling
        
        df_encoded = pd.get_dummies(final_df, columns=['Protocol'], drop_first=True)
        
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        
        numerical_features = final_df.select_dtypes(include='number').columns.tolist()
        df_encoded[numerical_features] = scaler.fit_transform(df_encoded[numerical_features])
        df_encoded.select_dtypes(include='number')

        df_encoded = df_encoded.iloc[4:]
        df_encoded = df_encoded.fillna(0)

        # Testing sample

        import joblib
        stored_model = joblib.load('cicids-2017_svc_model.joblib')
        y_pred = stored_model.predict(df_encoded)
        
        df_display["Label"] = pd.Series(y_pred)
        df_display["Protocol"] = df_display["Protocol"].map({
            0: "OTHER",
            6: "TCP",
            17: "UDP",
            1: "ICMP"
        })

        #print(result["Label"].value_counts())
         
        res = df_display.to_dict(orient="records")
        sort = sorted(res, key=lambda x: x["timestamp"], reverse=True)
        return sort
    

if __name__ == "__main__":
    obj = Parser()
    obj.process()
    
    
    