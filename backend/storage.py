import json
import os
from typing import List, Dict


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'history.json')


os.makedirs(DATA_DIR, exist_ok=True)




def _read_db() -> List[Dict]:
if not os.path.exists(DB_PATH):
return []
try:
with open(DB_PATH, 'r', encoding='utf-8') as f:
return json.load(f)
except Exception:
return []




def _write_db(items: List[Dict]):
with open(DB_PATH, 'w', encoding='utf-8') as f:
json.dump(items, f, ensure_ascii=False, indent=2)




def append_scan(result: Dict):
data = _read_db()
data.insert(0, result) # newest first
_write_db(data)




def get_recent(limit: int = 10) -> List[Dict]:
return _read_db()[:limit]




def get_summary() -> Dict:
items = _read_db()
status_counts = {'Safe': 0, 'Suspicious': 0, 'Fake': 0}
for it in items:
status_counts[it.get('status', 'Suspicious')] = status_counts.get(it.get('status', 'Suspicious'), 0) + 1
# Top 5 reasons (flatten flags)
from collections import Counter
all_flags = []
for it in items:
all_flags.extend(it.get('flags', []))
top_flags = [f for f, _ in Counter(all_flags).most_common(5)]


return {
'status_counts': status_counts,
'top_flags': top_flags,
}