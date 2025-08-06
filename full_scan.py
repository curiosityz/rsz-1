#!/usr/bin/env python3
from whole_tool import ECDSAAffineAttack
import json
from datetime import datetime

# Initialize with Chainstack
attack = ECDSAAffineAttack(
    chainstack_url="https://bitcoin-mainnet.core.chainstack.com/8995629f764c176fb4e05bdf4ab84277"
)

def scan_block(block_height):
    """Scan a single block and return its signatures"""
    try:
        # Get block hash
        block_hash = attack.chainstack_client._make_request('getblockhash', [block_height])
        print(f"\nAnalyzing block {block_height} ({block_hash})")

        # Get full block data
        block = attack.chainstack_client._make_request('getblock', [block_hash, 2])
        print(f"Found {len(block.get('tx', []))} transactions")

        # Extract signatures from witness data
        all_signatures = []
        for tx in block.get('tx', []):
            if tx.get('vin'):
                for vin in tx.get('vin', []):
                    if 'txinwitness' in vin:
                        for item in vin['txinwitness']:
                            if len(item) > 6 and item.startswith('30'):  # DER sequence marker
                                try:
                                    sig_bytes = bytes.fromhex(item[:-2])  # Remove sighash byte
                                    if sig_bytes[0] == 0x30:  # DER sequence
                                        total_len = sig_bytes[1]
                                        if len(sig_bytes) == total_len + 2:
                                            all_signatures.append(item)
                                except:
                                    continue

        return {
            'block_height': block_height,
            'block_hash': block_hash,
            'transaction_count': len(block.get('tx', [])),
            'signature_count': len(all_signatures),
            'signatures': all_signatures
        }
    except Exception as e:
        print(f"Error scanning block {block_height}: {str(e)}")
        return None

def main():
    try:
        # Parameters from the guide
        start_block = 750000
        end_block = 751000  # Scan 1000 blocks
        batch_size = 100  # Process in batches to manage memory

        start_time = datetime.now()
        print(f"Starting full scan from block {start_block} to {end_block}")
        
        total_signatures = []
        results = []

        # Process blocks in batches
        for batch_start in range(start_block, end_block, batch_size):
            batch_end = min(batch_start + batch_size, end_block)
            print(f"\nProcessing blocks {batch_start} to {batch_end-1}")

            batch_results = []
            for height in range(batch_start, batch_end):
                result = scan_block(height)
                if result:
                    batch_results.append(result)
                    total_signatures.extend(result['signatures'])

            # Analyze batch for vulnerabilities
            if batch_results:
                # Combine all transactions from the batch
                print("\nAnalyzing signatures from this batch...")
                result = attack.analyze_bitcoin_transactions([])
                result.signatures_extracted = len(total_signatures)

                if result.potential_vulnerabilities:
                    print(f"Found {len(result.potential_vulnerabilities)} potential vulnerabilities!")
                    
            results.extend(batch_results)

            # Export intermediate results
            with open(f'scan_results_{batch_start}_{batch_end-1}.json', 'w') as f:
                json.dump({
                    'blocks_scanned': batch_results,
                    'total_signatures': len(total_signatures),
                    'batch_start': batch_start,
                    'batch_end': batch_end-1
                }, f, indent=2)

        # Final analysis
        end_time = datetime.now()
        duration = end_time - start_time

        print("\nScan Complete!")
        print(f"Total time: {duration}")
        print(f"Blocks scanned: {len(results)}")
        print(f"Total signatures found: {len(total_signatures)}")

        # Export final results
        final_results = {
            'scan_info': {
                'start_block': start_block,
                'end_block': end_block-1,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration.total_seconds()
            },
            'summary': {
                'blocks_scanned': len(results),
                'total_signatures': len(total_signatures),
            },
            'block_details': results
        }

        with open('full_scan_results.json', 'w') as f:
            json.dump(final_results, f, indent=2)

    except Exception as e:
        print(f"Error during full scan: {str(e)}")

if __name__ == "__main__":
    main()
