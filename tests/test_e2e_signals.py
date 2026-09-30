import importlib.util
from pathlib import Path

path = Path(__file__).parents[1] / "scripts" / "run_studionet_e2e.py"
spec = importlib.util.spec_from_file_location("safe_call_e2e", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
signals = module.signals


def test_signals_accepts_leader_list():
    value = {"status_name":"FINALIZED","result_name":"MAJORITY_AGREE","consensus_data":{"leader_receipt":[{"mode":"leader","execution_result":"SUCCESS"}]}}
    assert signals(value) == ("FINALIZED", "MAJORITY_AGREE", "SUCCESS")


def test_signals_accepts_leader_object():
    value = {"status":"FINALIZED","consensus_result":"AGREE","consensus_data":{"leader_receipt":{"mode":"leader","execution_result":"SUCCESS"}}}
    assert signals(value) == ("FINALIZED", "AGREE", "SUCCESS")
