from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
print(ROOT)

DATASET_FILE = ROOT / "CIS_IDS_2017_compiled.csv"