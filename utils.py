import json

def extract_features_from_suricata(eve_event):
    # Basic features similar to NSL-KDD
    features = {
        'event_type': eve_event.get("event_type"),
        'duration': eve_event.get('flow', {}).get('age', 0),
        'protocol_type': eve_event.get('proto', 'tcp'),
        'service': eve_event.get('app_proto', 'unknown'),
        'flag': eve_event.get('tcp', {}).get('flags', '0'),
        'src_bytes': eve_event.get('flow', {}).get('bytes_toserver', 0),
        'dst_bytes': eve_event.get('flow', {}).get('bytes_toclient', 0)
    }
    return features