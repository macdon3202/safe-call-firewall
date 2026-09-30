"""Run live fail-closed and rejected-input paths with complete pre/post proof."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import time
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from run_studionet_e2e import load_wallets, plain, read, signals

RPC = "https://studio.genlayer.com/api"
EXPLORER = "https://explorer-studio.genlayer.com"


def snapshot(client, address, account):
    config = read(client, address, account, "get_config", [])
    return {"config": config, "assessments": [read(client, address, account, "get_assessment", [i]) for i in range(1, int(config["assessment_count"]) + 1)]}


def wait_final(client, tx):
    last_error = None
    for attempt in range(200):
        try:
            info = plain(client.get_transaction(tx)); status, consensus, execution = signals(info)
            if status == "FINALIZED": return {"status":status,"consensus":consensus,"execution":execution,"result_name":info.get("result_name")}
        except Exception as error:
            last_error = str(error)
        time.sleep(3)
    raise TimeoutError({"tx":tx,"last_error":last_error})


def main():
    if len(sys.argv) != 2: raise SystemExit("usage: run_live_adversarial.py ADDRESS")
    address=sys.argv[1]; load_wallets()
    wallet_a=create_account(os.environ["SERVICE_LEDGER_KEY_A"]); wallet_b=create_account(os.environ["SERVICE_LEDGER_KEY_B"])
    client=create_client(chain=studionet,account=wallet_a,endpoint=RPC)
    cases=[]
    invalid=[
        ("UNSUPPORTED_CHAIN",wallet_a,["POLYGON","0x"+"11"*32,"ROUTINE_OPERATIONS"]),
        ("MALFORMED_HASH",wallet_b,["SEPOLIA","0x1234","ROUTINE_OPERATIONS"]),
        ("UNKNOWN_POLICY",wallet_a,["SEPOLIA","0x"+"22"*32,"CUSTOM_POLICY"]),
    ]
    for name,wallet,args in invalid:
        before=snapshot(client,address,wallet)
        tx=str(client.write_contract(address=address,function_name="analyze_safe_transaction",account=wallet,args=args,value=0))
        final=wait_final(client,tx); after=snapshot(client,address,wallet)
        if final["execution"]=="SUCCESS" or before!=after: raise AssertionError({"name":name,"final":final,"before":before,"after":after})
        cases.append({"name":name,"wallet":str(wallet.address),"args":args,"transaction":{"hash":tx,"url":f"{EXPLORER}/tx/{tx}",**final},"pre_post_equal":True})
    # A validly shaped locator whose official source record does not exist must
    # create a non-positive UNRESOLVED certificate, never CLEAR/BLOCKED.
    args=["SEPOLIA","0x"+"ff"*32,"ROUTINE_OPERATIONS"]
    before=snapshot(client,address,wallet_b)
    tx=str(client.write_contract(address=address,function_name="analyze_safe_transaction",account=wallet_b,args=args,value=0))
    final=wait_final(client,tx)
    if final["consensus"] not in {"MAJORITY_AGREE","AGREE","ACCEPTED"} or final["execution"]!="SUCCESS": raise AssertionError({"name":"SOURCE_NOT_FOUND","final":final})
    after=snapshot(client,address,wallet_b); created=after["assessments"][-1]
    if int(after["config"]["assessment_count"])!=int(before["config"]["assessment_count"])+1 or created["state"]!="UNRESOLVED" or created["reason"]!="SOURCE_NOT_VERIFIED": raise AssertionError({"before":before,"after":after})
    cases.append({"name":"SOURCE_NOT_FOUND","wallet":str(wallet_b.address),"args":args,"transaction":{"hash":tx,"url":f"{EXPLORER}/tx/{tx}",**final},"assessment":created})
    evidence={"contract":address,"contract_url":f"{EXPLORER}/address/{address}","cases":cases,"final_config":after["config"]}
    root=Path(__file__).resolve().parents[1];(root/"docs"/"studionet-adversarial.json").write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    rows=["# StudioNet adversarial evidence","",f"- Contract: [{address}]({evidence['contract_url']})","", "| Path | Transaction | Final result | State proof |","|---|---|---|---|"]
    for c in cases:
        proof=f"certificate #{c['assessment']['id']} `{c['assessment']['state']}`" if "assessment" in c else "complete pre-state equals post-state"
        rows.append(f"| `{c['name']}` | [tx]({c['transaction']['url']}) | {c['transaction']['status']} / {c['transaction']['consensus']} / {c['transaction']['execution']} | {proof} |")
    (root/"docs"/"STUDIONET_ADVERSARIAL.md").write_text("\n".join(rows)+"\n",encoding="utf-8")
    print(json.dumps(evidence,indent=2))


if __name__=="__main__": main()
