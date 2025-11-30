import argparse
from core import mitm_pipeline

""" src/cli.py: Command-line interface for the MITM attack framework."""

def main():
    parser = argparse.ArgumentParser(description="MITM Attack Framework CLI: ARP + DNS + SSL")
    parser.add_argument(
        "--mode",
        default="arp+dns+ssl",
        help="Combination of attacks: e.g. 'arp', 'dns', 'ssl', 'arp+dns'"
    )

    args = parser.parse_args()
    mitm_pipeline.run(args.mode)

if __name__ == "__main__":
    main()

# Usage: python3 -m src.cli --mode arp+dns