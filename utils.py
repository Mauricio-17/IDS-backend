import json
import re

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



def is_valid_password(password: str) -> bool:
    """
    Validates a password that must contain:
      - at least one uppercase letter
      - at least one number
      - at least 8 characters in total
    """
    pattern = r'^(?=.*[A-Z])(?=.*\d).{9,}$'
    return bool(re.match(pattern, password))

"""
# Example usage:
passwords = ["hello", "Hello", "Hello1", "Hello123", "TestPass1"]

for pwd in passwords:
    print(pwd, "->", is_valid_password(pwd))
"""