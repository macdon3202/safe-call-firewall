"""Read the active StudioNet deployment without mutating it."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet


def main() -> None:
    if len(sys.argv) != 2: raise SystemExit("usage: inspect_deployment.py CONTRACT_ADDRESS")
    root = Path(__file__).resolve().parents[2]
    for raw in (root / "secrets" / "genlayer-test-wallets.env").read_text(encoding="utf-8").splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            key, value = raw.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'\"").strip("<>"))
    account = create_account(os.environ["SERVICE_LEDGER_KEY_A"])
    client = create_client(chain=studionet, account=account, endpoint="https://studio.genlayer.com/api")
    value = client.read_contract(address=sys.argv[1], function_name="get_config", args=[], account=account)
    print(json.dumps(value, indent=2, default=str))


if __name__ == "__main__": main()
