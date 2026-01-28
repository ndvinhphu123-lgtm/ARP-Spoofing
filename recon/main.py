import asyncio
import argparse
import logging
import sys
from config import ScanConfig
from orchestrator import ReconOrchestrator

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def parse_args():
    parser = argparse.ArgumentParser(description="ReconElite Tool")
    parser.add_argument("target", help="Target domain")
    parser.add_argument("--dry-run", action="store_true")
    # Thêm các arg khác nếu cần từ file cũ
    return ScanConfig(target_domain=parser.parse_args().target, dry_run=parser.parse_args().dry_run)

async def main():
    config = parse_args()
    orch = ReconOrchestrator(config)
    print(f"🚀 Starting scan on {config.target_domain}...")
    res = await orch.run()
    if res:
        print(f"✅ Scan Complete! Found {len(res.assets)} hosts.")
        for ip, asset in res.assets.items():
            print(f" - {ip}: {list(asset.ports.keys())}")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())