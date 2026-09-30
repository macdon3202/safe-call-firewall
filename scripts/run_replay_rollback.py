"""Prove a replayed assessment fails and leaves authoritative state unchanged."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import time
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from run_studionet_e2e import plain, signals


def main() -> None:
    if len(sys.argv) != 2: raise SystemExit("usage: run_replay_rollback.py CONTRACT_ADDRESS")
    root = Path(__file__).resolve().parents[2]
    for raw in (root / "secrets" / "genlayer-test-wallets.env").read_text(encoding="utf-8").splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            key, value = raw.split("=", 1); os.environ.setdefault(key.strip(), value.strip().strip("'\"").strip("<>"))
    account = create_account(os.environ["SERVICE_LEDGER_KEY_B"])
    client = create_client(chain=studionet, account=account, endpoint="https://studio.genlayer.com/api")
    address = sys.argv[1]
    read = lambda method, args: plain(client.read_contract(address=address, function_name=method, args=args, account=account))
    before_config = read("get_config", [])
    before = {"config": before_config, "assessments": [read("get_assessment", [i]) for i in range(1, int(before_config["assessment_count"]) + 1)]}
    args = ["SEPOLIA", "0x736a2748f27f55f951ae97072a5520e4a8b9e14a3a01344794243b530d44be12", "ROUTINE_OPERATIONS"]
    tx = str(client.write_contract(address=address, function_name="analyze_safe_transaction", account=account, args=args, value=0))
    final = None
    for _ in range(100):
        try:
            info = plain(client.get_transaction(tx)); status, consensus, execution = signals(info)
            if status == "FINALIZED":
                final = {"status": status, "consensus": consensus, "execution": execution, "result_name": info.get("result_name")}
                break
        except Exception:
            pass
        time.sleep(3)
    if final is None: raise TimeoutError(tx)
    after_config = read("get_config", [])
    after = {"config": after_config, "assessments": [read("get_assessment", [i]) for i in range(1, int(after_config["assessment_count"]) + 1)]}
    if final["execution"] == "SUCCESS" or before != after: raise AssertionError({"final": final, "before": before, "after": after})
    evidence = {"path":"REPLAY_ROLLBACK","wallet":str(account.address),"args":args,"transaction":{"hash":tx,"url":f"https://explorer-studio.genlayer.com/tx/{tx}",**final},"pre_post_equal":True,"before":before,"after":after}
    (Path(__file__).resolve().parents[1]/"docs"/"replay-rollback.json").write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(evidence,indent=2))


if __name__ == "__main__": main()
