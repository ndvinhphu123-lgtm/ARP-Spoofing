import json
import hashlib
from pathlib import Path
from typing import Optional, Any

class ScanCache:
    def __init__(self, cache_dir: str = "./cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_key(self, target: str, scan_type: str) -> str:
        key = f"{target}:{scan_type}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def get(self, target: str, scan_type: str) -> Optional[Any]:
        cache_key = self._get_cache_key(target, scan_type)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                return None
        return None
    
    def set(self, target: str, scan_type: str, data: Any):
        cache_key = self._get_cache_key(target, scan_type)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)