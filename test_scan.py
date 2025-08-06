"""
Test script for scanning Bitcoin signatures in block 750000
"""
import json
import secp256k1 as ice
from rsz_rdiff_scan import get_rs
from rsz_rdiff_scan import split_sig_pieces

def extract_sigs_from_witness(witness_data):
    """Extract signatures from witness data"""
    sigs = []
    for item in witness_data:
        if isinstance(item, str) and len(item) > 8:  # Min sig length
            try:
                # Remove any SIGHASH byte from end
                sig = item[:-2] if item[-2:] in ['01', '02', '03', '81', '82', '83'] else item
                
                # Only process if looks like DER signature
                if len(sig) > 8 and sig.startswith('30'):
                    r, s = get_rs(sig)
                    if r and s:
                        sigs.append((r, s))
            except Exception as e:
                print(f"Error processing witness item: {e}")
                continue
    return sigs

def process_transaction(tx):
    """Process a single transaction to extract signatures"""
    sigs = []
    
    # Process legacy inputs
    for vin in tx.get('vin', []):
        scriptSig = vin.get('scriptSig', {}).get('hex', '')
        if scriptSig:
            try:
                # Extract from scriptSig
                r, s, pub = split_sig_pieces(scriptSig)
                if r and s:
                    sigs.append((r, s))
            except:
                pass
        
        # Process witness data
        witness = vin.get('txinwitness', [])
        witness_sigs = extract_sigs_from_witness(witness)
        sigs.extend(witness_sigs)
    
    return sigs

def main():
    print("Loading block data...")
    with open('block_750000.json') as f:
        block = json.load(f)
    
    print(f"Processing {len(block['tx'])} transactions...")
    
    all_sigs = []
    r_values = {}  # Track R-value occurrences
    
    for tx in block['tx']:
        tx_sigs = process_transaction(tx)
        if tx_sigs:
            all_sigs.extend(tx_sigs)
            
            # Track R-value occurrences
            for r, s in tx_sigs:
                r_int = int(r, 16)
                if r_int in r_values:
                    r_values[r_int].append(s)
                else:
                    r_values[r_int] = [s]
    
    print(f"\nFound {len(all_sigs)} total signatures")
    print(f"Found {len(r_values)} unique R-values")
    
    # Check for reused R-values
    reused = {r: sigs for r, sigs in r_values.items() if len(sigs) > 1}
    if reused:
        print(f"\nFound {len(reused)} reused R-values!")
        for r, s_list in reused.items():
            print(f"R-value {hex(r)} used {len(s_list)} times")
    else:
        print("\nNo reused R-values found")

if __name__ == '__main__':
    main()
