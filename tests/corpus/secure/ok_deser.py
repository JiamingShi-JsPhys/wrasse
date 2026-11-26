import json
import yaml

def load(raw):
    return json.loads(raw)

def load_yaml(raw):
    return yaml.safe_load(raw)
