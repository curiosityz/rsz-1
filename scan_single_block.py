#!/usr/bin/env python3
from whole_tool import ECDSAAffineAttack
import json

# Initialize with Chainstack
attack = ECDSAAffineAttack(
    chainstack_url="https://bitcoin-mainnet.core.chainstack.com/8995629f764c176fb4e05bdf4ab84277"
)

try:
    # First get the block hash
    block_hash = attack.chainstack_client._make_request('getblockhash', [750000])
    print(f"Got block hash: {block_hash}")

    # Then get full block data
    block = attack.chainstack_client._make_request('getblock', [block_hash, 2])
    print(f"Got block with {len(block.get('tx', []))} transactions")

    # Save full block data for inspection
    with open('block_750000.json', 'w') as f:
        json.dump(block, f, indent=2)

    # Look at non-coinbase transactions
    print("\nChecking first few non-coinbase transactions:")
    for tx in block['tx'][1:6]:  # Skip coinbase, look at next 5
        print(f"\nTransaction {tx.get('txid')}:")
        print(f"size: {tx.get('size')} bytes")
        print(f"Number of inputs: {len(tx.get('vin', []))}")
        print(f"Number of outputs: {len(tx.get('vout', []))}")
        
        # Look at first input's scriptSig/witness data
        if tx.get('vin'):
            first_input = tx['vin'][0]
            print("First input details:")
            if 'scriptSig' in first_input:
                print(f"scriptSig: {first_input['scriptSig'].get('hex', '')}")
            if 'txinwitness' in first_input:
                print(f"witness data: {first_input['txinwitness']}")

    # Now analyze it for signatures
    # Use a dedicated function to analyze a single transaction
    def extract_sigs_from_witness(witness_data):
        sigs = []
        if not witness_data:
            return sigs
        
        # Look for DER signatures in witness data
        for item in witness_data:
            if len(item) > 6 and item.startswith('30'): # DER sequence marker
                try:
                    sig_bytes = bytes.fromhex(item[:-2])  # Remove sighash byte
                    # Verify this is a valid DER signature
                    if sig_bytes[0] == 0x30:  # DER sequence
                        total_len = sig_bytes[1]
                        if len(sig_bytes) == total_len + 2:
                            sigs.append(item)
                except:
                    continue
        return sigs

    # Find witness transactions with signatures
    sig_count = 0
    transactions = block.get('tx', [])[1:]  # Skip coinbase
    for tx_idx, tx in enumerate(transactions):
        if tx.get('vin'):
            for vin in tx.get('vin', []):
                if 'txinwitness' in vin:
                    sigs = extract_sigs_from_witness(vin['txinwitness'])
                    if sigs:
                        print(f"\nFound {len(sigs)} signatures in transaction {tx.get('txid', '')} input:")
                        for sig in sigs:
                            print(f"Signature: {sig[:30]}...")  # Show start of signature
                            sig_count += 1
                        if sig_count >= 5:  # Just show first few for demonstration
                            break
    
    # Now analyze full block
    print(f"\nAnalyzing all {len(block.get('tx', []))} transactions...")
    tx_hex_list = [tx.get('hex', '') for tx in block.get('tx', [])]
    
    # Collect all signatures from witness data
    all_signatures = []
    for tx in block.get('tx', []):
        if tx.get('vin'):
            for vin in tx.get('vin', []):
                if 'txinwitness' in vin:
                    sigs = extract_sigs_from_witness(vin['txinwitness'])
                    all_signatures.extend(sigs)
    
    if tx_hex_list:
        # Create an analysis result with the collected signatures
        result = attack.analyze_bitcoin_transactions(
            tx_hex_list=tx_hex_list
        )

        # Add the collected signatures to the result
        result.signatures_extracted = len(all_signatures)
        
        # Export results
        attack.export_analysis_results(
            result=result,
            filename="block_750000_analysis.json",
            include_signatures=True
        )
        print(f"\nAnalysis complete:")
        print(f"Found {len(all_signatures)} total signatures")
        print(f"Found {len(result.potential_vulnerabilities)} potential vulnerabilities")

except Exception as e:
    print(f"Error: {str(e)}")
