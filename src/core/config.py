import pathlib
import yaml

CONFIG_PATH = pathlib.Path(__file__).resolve().parents[2] / "env" / "topology.yml"

def load_config():
    with open(CONFIG_PATH, 'r') as file:
        config = yaml.safe_load(file)
    return config