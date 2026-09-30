"""Run reviewed SafeCall resources from two non-deployer wallets on StudioNet."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import time
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet

RPC = "https://studio.genlayer.com/api"
EXPLORER = "https://explorer-studio.genlayer.com"
ROOT = Path(__file__).resolve().parents[1]


def load_wallets() -> None:
    path = ROOT.parent / "secrets" / "genlayer-test-wallets.env"
    for raw in path.read_text(encoding="utf-8").splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            key, value = raw.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'\"").strip("<>"))


def plain(value):
    if isinstance(value, dict): return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [plain(v) for v in value]
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)


def read(client, address, account, method, args):
    last = None
    for attempt in range(8):
        try: return plain(client.read_contract(address=address, function_name=method, args=args, account=account))
        except Exception as error:
            last = error; time.sleep(2 + attempt)
    raise last


def signals(info):
    status = str(info.get("status_name") or info.get("statusName") or info.get("status") or "UNKNOWN").upper()
    consensus = str(info.get("result_name") or info.get("consensus_result_name") or info.get("consensus_result") or "UNKNOWN").upper()
    data = info.get("consensus_data") if isinstance(info.get("consensus_data"), dict) else {}
    receipts = data.get("leader_receipt") or data.get("validators") or []
    if isinstance(receipts, dict): receipts = [receipts]
    leader = next((r for r in receipts if isinstance(r, dict) and str(r.get("mode", "")).lower() == "leader"), receipts[0] if receipts else {})
    execution = str(leader.get("execution_result") or info.get("execution_result") or "UNKNOWN").upper()
    return status, consensus, execution


def send(client, address, account, args):
    tx = str(client.write_contract(address=address, function_name="analyze_safe_transaction", account=account, args=args, value=0))
    print(json.dumps({"submitted": tx, "args": args}), flush=True)
    for _ in range(200):
        status, consensus, execution = signals(plain(client.get_transaction(tx)))
        if status == "FINALIZED":
            if consensus not in {"MAJORITY_AGREE", "AGREE", "ACCEPTED"} or execution != "SUCCESS":
                raise AssertionError((status, consensus, execution, tx))
            return {"hash": tx, "url": f"{EXPLORER}/tx/{tx}", "status": status, "consensus": consensus, "execution": execution}
        time.sleep(3)
    raise TimeoutError(tx)


def main() -> None:
    if len(sys.argv) != 2: raise SystemExit("usage: run_studionet_e2e.py CONTRACT_ADDRESS")
    address = sys.argv[1]
    load_wallets()
    wallet_a = create_account(os.environ["SERVICE_LEDGER_KEY_A"])
    wallet_b = create_account(os.environ["SERVICE_LEDGER_KEY_B"])
    client = create_client(chain=studionet, account=wallet_a, endpoint=RPC)
    cases = [
        ("wallet_a", wallet_a, os.environ.get("SAFE_CALL_CHAIN_A", ""), os.environ.get("SAFE_CALL_HASH_A", ""), os.environ.get("SAFE_CALL_POLICY_A", "ROUTINE_OPERATIONS"), os.environ.get("SAFE_CALL_EXPECT_A", "")),
        ("wallet_b", wallet_b, os.environ.get("SAFE_CALL_CHAIN_B", ""), os.environ.get("SAFE_CALL_HASH_B", ""), os.environ.get("SAFE_CALL_POLICY_B", "STRICT_NO_ADMIN"), os.environ.get("SAFE_CALL_EXPECT_B", "")),
    ]
    if any(not chain or not tx_hash or not expected for _, _, chain, tx_hash, _, expected in cases):
        raise SystemExit("Set SAFE_CALL_CHAIN/HASH/EXPECT_A and _B after documenting two exact live resources")
    cfg = read(client, address, wallet_a, "get_config", [])
    if cfg.get("version") != "SAFE_CALL_FIREWALL_V2_2": raise AssertionError(cfg)
    evidence = {"network": "studionet", "contract": address, "contract_url": f"{EXPLORER}/address/{address}", "initial_config": cfg, "cases": []}
    for label, wallet, chain, tx_hash, policy, expected in cases:
        before = int(read(client, address, wallet, "get_config", [])["assessment_count"])
        receipt = send(client, address, wallet, [chain, tx_hash, policy])
        after = read(client, address, wallet, "get_config", [])
        assessment = read(client, address, wallet, "get_assessment", [int(after["assessment_count"])])
        if int(after["assessment_count"]) != before + 1 or assessment["state"] != expected:
            raise AssertionError({"expected": expected, "before": before, "after": after, "assessment": assessment})
        evidence["cases"].append({"wallet_role": label, "wallet": str(wallet.address), "input": {"chain": chain, "safe_tx_hash": tx_hash, "policy": policy}, "expected": expected, "transaction": receipt, "assessment": assessment})
    (ROOT / "docs" / "studionet-e2e.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    rows = ["# StudioNet E2E evidence", "", f"- Contract: [{address}]({evidence['contract_url']})", "- Deployer privilege: none", "", "| Path | Wallet | Source | Transaction | Stored result |", "|---|---|---|---|---|"]
    for case in evidence["cases"]:
        source = f"{case['input']['chain']} `{case['input']['safe_tx_hash']}`"
        rows.append(f"| {case['expected']} | `{case['wallet']}` | {source} | [finalized success]({case['transaction']['url']}) | certificate #{case['assessment']['id']} `{case['assessment']['state']}` |")
    (ROOT / "docs" / "STUDIONET_E2E.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__": main()
