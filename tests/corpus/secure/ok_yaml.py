import yaml


def load(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)
