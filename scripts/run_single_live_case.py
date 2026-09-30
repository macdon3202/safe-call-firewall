"""Run one pre-manifested SafeCall live case and require exact readback."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from run_studionet_e2e import load_wallets, plain, read, send


def main() -> None:
    if len(sys.argv) != 7: raise SystemExit("usage: run_single_live_case.py ADDRESS WALLET_KEY_NAME CHAIN HASH POLICY EXPECTED")
    address, key_name, chain, tx_hash, policy, expected = sys.argv[1:]
    load_wallets(); account = create_account(os.environ[key_name])
    client = create_client(chain=studionet, account=account, endpoint="https://studio.genlayer.com/api")
    before = read(client, address, account, "get_config", [])
    receipt = send(client, address, account, [chain, tx_hash, policy])
    after = read(client, address, account, "get_config", [])
    assessment = read(client, address, account, "get_assessment", [int(after["assessment_count"])])
    if int(after["assessment_count"]) != int(before["assessment_count"]) + 1 or assessment["state"] != expected:
        raise AssertionError({"before":before,"after":after,"expected":expected,"assessment":assessment})
    evidence={"wallet":str(account.address),"input":{"chain":chain,"safe_tx_hash":tx_hash,"policy":policy},"expected":expected,"transaction":receipt,"assessment":assessment}
    out=Path(__file__).resolve().parents[1]/"docs"/f"live-{assessment['id']}.json";out.write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(evidence,indent=2))


if __name__ == "__main__": main()
