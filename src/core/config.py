import pathlib
import yaml

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "src" / "env" / "topology.yml"

def load_config():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"Topology config not found at: {CONFIG_PATH}"
        )

    with open(CONFIG_PATH, "r") as file:
        config = yaml.safe_load(file)

    return config

