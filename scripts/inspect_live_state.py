"""Inspect public transaction and complete relevant SafeCall readback."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet


def plain(value):
    if isinstance(value, dict): return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [plain(v) for v in value]
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)


def main() -> None:
    if len(sys.argv) < 2: raise SystemExit("usage: inspect_live_state.py ADDRESS [TX_HASH]")
    root = Path(__file__).resolve().parents[2]
    for raw in (root / "secrets" / "genlayer-test-wallets.env").read_text(encoding="utf-8").splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            key, value = raw.split("=", 1); os.environ.setdefault(key.strip(), value.strip().strip("'\"").strip("<>"))
    account = create_account(os.environ["SERVICE_LEDGER_KEY_A"])
    client = create_client(chain=studionet, account=account, endpoint="https://studio.genlayer.com/api")
    address = sys.argv[1]
    config = plain(client.read_contract(address=address, function_name="get_config", args=[], account=account))
    assessments = [plain(client.read_contract(address=address, function_name="get_assessment", args=[i], account=account)) for i in range(1, int(config["assessment_count"]) + 1)]
    result = {"config": config, "assessments": assessments}
    if len(sys.argv) > 2: result["transaction"] = plain(client.get_transaction(sys.argv[2]))
    print(json.dumps(result, indent=2))


if __name__ == "__main__": main()
