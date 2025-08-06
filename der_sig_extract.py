"""
Complete Bitcoin transaction signature parser that extracts R, S, Z from ALL signature types.
Supports P2PKH, P2SH, P2WPKH, P2WSH, P2TR, and multisig transactions.
Uses python-bitcoinlib for proper transaction parsing.
"""
import hashlib
import struct
from typing import List, Tuple, Optional, Union, Dict, Any
from enum import Enum

# bitcoin-lib imports
import bitcoin
from bitcoin.core import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin.core.serialize import *
from bitcoin.segwit_addr import encode as bech32_encode, decode as bech32_decode

class SigHashType(Enum):
    """Bitcoin signature hash types"""
    SIGHASH_ALL = 0x01
    SIGHASH_NONE = 0x02
    SIGHASH_SINGLE = 0x03
    SIGHASH_ANYONECANPAY = 0x80
    SIGHASH_ALL_ANYONECANPAY = 0x81
    SIGHASH_NONE_ANYONECANPAY = 0x82
    SIGHASH_SINGLE_ANYONECANPAY = 0x83
    SIGHASH_DEFAULT = 0x00  # Taproot default

class ScriptType(Enum):
    """Bitcoin script types"""
    P2PKH = "p2pkh"
    P2SH = "p2sh"
    P2WPKH = "p2wpkh"
    P2WSH = "p2wsh"
    P2TR = "p2tr"
    MULTISIG = "multisig"
    P2PK = "p2pk"
    UNKNOWN = "unknown"

def parse_der_signature(signature_bytes: bytes) -> Tuple[int, int]:
    """
    Parses a DER-encoded ECDSA signature to extract r and s integers.
    Handles all standard DER encodings including edge cases.
    """
    if len(signature_bytes) < 8:  # Minimum valid DER signature length
        raise ValueError(f"Signature too short: {len(signature_bytes)} bytes")
    
    # Check DER sequence tag
    if signature_bytes[0] != 0x30:
        raise ValueError(f"Invalid DER signature: missing sequence tag, got 0x{signature_bytes[0]:02x}")
    
    # Get total length
    total_length = signature_bytes[1]
    if len(signature_bytes) != total_length + 2:
        raise ValueError(f"Invalid DER signature: length mismatch {len(signature_bytes)} != {total_length + 2}")
    
    pos = 2
    
    # Parse r value
    if pos >= len(signature_bytes) or signature_bytes[pos] != 0x02:
        raise ValueError(f"Invalid DER signature: missing r integer tag at position {pos}")
    pos += 1
    
    r_length = signature_bytes[pos]
    pos += 1
    
    if r_length == 0:
        raise ValueError("Invalid DER signature: r length is zero")
    
    if pos + r_length > len(signature_bytes):
        raise ValueError(f"Invalid DER signature: r value extends beyond signature")
    
    r_bytes = signature_bytes[pos:pos + r_length]
    
    # Handle negative values and leading zeros in DER encoding
    if r_bytes[0] & 0x80:
        raise ValueError("Invalid DER signature: r value is negative")
    
    r = int.from_bytes(r_bytes, byteorder='big', signed=False)
    pos += r_length
    
    # Parse s value
    if pos >= len(signature_bytes) or signature_bytes[pos] != 0x02:
        raise ValueError(f"Invalid DER signature: missing s integer tag at position {pos}")
    pos += 1
    
    s_length = signature_bytes[pos]
    pos += 1
    
    if s_length == 0:
        raise ValueError("Invalid DER signature: s length is zero")
    
    if pos + s_length > len(signature_bytes):
        raise ValueError(f"Invalid DER signature: s value extends beyond signature")
    
    s_bytes = signature_bytes[pos:pos + s_length]
    
    if s_bytes[0] & 0x80:
        raise ValueError("Invalid DER signature: s value is negative")
    
    s = int.from_bytes(s_bytes, byteorder='big', signed=False)
    
    # Verify we consumed the entire signature
    if pos + s_length != len(signature_bytes):
        raise ValueError(f"Invalid DER signature: extra bytes at end")
    
    return r, s

def detect_script_type(scriptPubKey: CScript, scriptSig: CScript = None, witness: List[bytes] = None) -> ScriptType:
    """Detects the type of Bitcoin script based on scriptPubKey and spending data"""
    
    # Convert to raw bytes for analysis
    spk_bytes = bytes(scriptPubKey)
    
    # P2PKH: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
    if (len(spk_bytes) == 25 and 
        spk_bytes[0] == OP_DUP and spk_bytes[1] == OP_HASH160 and spk_bytes[2] == 20 and
        spk_bytes[23] == OP_EQUALVERIFY and spk_bytes[24] == OP_CHECKSIG):
        return ScriptType.P2PKH
    
    # P2SH: OP_HASH160 <20-byte hash> OP_EQUAL
    if (len(spk_bytes) == 23 and 
        spk_bytes[0] == OP_HASH160 and spk_bytes[1] == 20 and spk_bytes[22] == OP_EQUAL):
        return ScriptType.P2SH
    
    # P2WPKH: OP_0 <20-byte pubkey hash>
    if len(spk_bytes) == 22 and spk_bytes[0] == OP_0 and spk_bytes[1] == 20:
        return ScriptType.P2WPKH
    
    # P2WSH: OP_0 <32-byte script hash>
    if len(spk_bytes) == 34 and spk_bytes[0] == OP_0 and spk_bytes[1] == 32:
        return ScriptType.P2WSH
    
    # P2TR: OP_1 <32-byte taproot output>
    if len(spk_bytes) == 34 and spk_bytes[0] == OP_1 and spk_bytes[1] == 32:
        return ScriptType.P2TR
    
    # P2PK: <33 or 65 byte pubkey> OP_CHECKSIG
    if ((len(spk_bytes) == 35 and spk_bytes[0] == 33) or 
        (len(spk_bytes) == 67 and spk_bytes[0] == 65)) and spk_bytes[-1] == OP_CHECKSIG:
        return ScriptType.P2PK
    
    # Check for multisig patterns
    if len(spk_bytes) > 3:
        # Standard multisig: OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG
        if (spk_bytes[0] >= OP_1 and spk_bytes[0] <= OP_16 and  # OP_1 to OP_16
            spk_bytes[-1] == OP_CHECKMULTISIG and
            spk_bytes[-2] >= OP_1 and spk_bytes[-2] <= OP_16):
            return ScriptType.MULTISIG
    
    return ScriptType.UNKNOWN

def extract_signatures_and_pubkeys(scriptSig: CScript, witness: List[bytes], 
                                 script_type: ScriptType) -> List[Tuple[bytes, Optional[bytes]]]:
    """
    Extract signatures and corresponding public keys from scriptSig and witness data.
    Returns list of (signature_bytes, pubkey_bytes) tuples.
    """
    results = []
    
    try:
        if script_type == ScriptType.P2PKH:
            # P2PKH scriptSig: <sig> <pubkey>
            ops = list(scriptSig)
            if len(ops) >= 2:
                sig_data = ops[0]
                pubkey_data = ops[1]
                if isinstance(sig_data, bytes) and isinstance(pubkey_data, bytes):
                    if len(sig_data) > 6 and len(pubkey_data) in [33, 65]:  # Valid sig and pubkey lengths
                        results.append((sig_data, pubkey_data))
        
        elif script_type == ScriptType.P2PK:
            # P2PK scriptSig: <sig>
            ops = list(scriptSig)
            if len(ops) >= 1:
                sig_data = ops[0]
                if isinstance(sig_data, bytes) and len(sig_data) > 6:
                    results.append((sig_data, None))  # No pubkey in scriptSig for P2PK
        
        elif script_type == ScriptType.P2WPKH:
            # P2WPKH witness: <signature> <pubkey>
            if len(witness) >= 2:
                sig_data = witness[0]
                pubkey_data = witness[1]
                if len(sig_data) > 6 and len(pubkey_data) in [33, 65]:
                    results.append((sig_data, pubkey_data))
        
        elif script_type == ScriptType.P2WSH:
            # P2WSH witness: <sig1> [<sig2> ...] <witnessScript>
            if len(witness) >= 2:
                witness_script = witness[-1]  # Last element is the witness script
                witness_script_obj = CScript(witness_script)
                
                # Determine the type of witness script
                inner_type = detect_script_type(witness_script_obj)
                
                if inner_type == ScriptType.MULTISIG:
                    # Extract M and N from multisig script
                    ws_bytes = bytes(witness_script_obj)
                    if len(ws_bytes) > 2:
                        m = ws_bytes[0] - OP_1 + 1 if ws_bytes[0] >= OP_1 and ws_bytes[0] <= OP_16 else 0
                        n = ws_bytes[-2] - OP_1 + 1 if ws_bytes[-2] >= OP_1 and ws_bytes[-2] <= OP_16 else 0
                        
                        # Signatures are in witness[1:m+1] (witness[0] is empty for multisig)
                        sig_start = 1
                        for i in range(sig_start, min(len(witness) - 1, sig_start + n)):
                            if len(witness[i]) > 6:  # Valid signature length
                                results.append((witness[i], None))  # Pubkeys are in witness script
                
                elif inner_type == ScriptType.P2PKH:
                    # Nested P2WPKH-in-P2WSH (rare but possible)
                    if len(witness) >= 3:
                        sig_data = witness[0]
                        pubkey_data = witness[1]
                        if len(sig_data) > 6 and len(pubkey_data) in [33, 65]:
                            results.append((sig_data, pubkey_data))
        
        elif script_type == ScriptType.P2SH:
            # P2SH scriptSig: [<sig1> ...] <redeemScript>
            ops = list(scriptSig)
            if len(ops) >= 2:
                redeem_script_data = ops[-1]
                if isinstance(redeem_script_data, bytes):
                    redeem_script = CScript(redeem_script_data)
                    inner_type = detect_script_type(redeem_script)
                    
                    if inner_type == ScriptType.MULTISIG:
                        # Multisig P2SH: OP_0 <sig1> [<sig2> ...] <redeemScript>
                        # ops[0] should be empty/OP_0, signatures are ops[1:-1]
                        for i in range(1, len(ops) - 1):
                            sig_data = ops[i]
                            if isinstance(sig_data, bytes) and len(sig_data) > 6:
                                results.append((sig_data, None))
                    
                    elif inner_type == ScriptType.P2WPKH:
                        # P2WPKH-in-P2SH: scriptSig is empty, check witness
                        if len(witness) >= 2:
                            sig_data = witness[0]
                            pubkey_data = witness[1]
                            if len(sig_data) > 6 and len(pubkey_data) in [33, 65]:
                                results.append((sig_data, pubkey_data))
                    
                    elif inner_type == ScriptType.P2WSH:
                        # P2WSH-in-P2SH: scriptSig contains witness program, check witness
                        return extract_signatures_and_pubkeys(CScript(), witness, ScriptType.P2WSH)
        
        elif script_type == ScriptType.MULTISIG:
            # Direct multisig scriptSig: OP_0 <sig1> [<sig2> ...]
            ops = list(scriptSig)
            if len(ops) >= 2:
                # First op should be OP_0 for multisig
                for i in range(1, len(ops)):
                    sig_data = ops[i]
                    if isinstance(sig_data, bytes) and len(sig_data) > 6:
                        results.append((sig_data, None))
        
        elif script_type == ScriptType.P2TR:
            # P2TR witness: <signature> [<script> <control>] for key path or script path
            if len(witness) >= 1:
                sig_data = witness[0]
                if len(sig_data) in [64, 65]:  # Schnorr signature length
                    results.append((sig_data, None))
                
                # For script path spending, there might be additional signatures in the script
                if len(witness) >= 3:  # script path: [...] <script> <control>
                    script_data = witness[-2]
                    try:
                        script = CScript(script_data)
                        # Parse script for additional signatures (implementation depends on script)
                        # This is complex and script-dependent
                        pass
                    except:
                        pass
    
    except Exception as e:
        print(f"Warning: Error extracting signatures for {script_type}: {e}")
    
    return results

def calculate_legacy_sighash(tx: CTransaction, input_index: int, scriptPubKey: CScript, 
                           sighash_type: int) -> bytes:
    """Calculate signature hash for legacy (non-segwit) transactions"""
    try:
        # Use bitcoin-lib's SignatureHash function
        sighash = SignatureHash(scriptPubKey, tx, input_index, sighash_type)
        return sighash
    except Exception as e:
        print(f"Error calculating legacy sighash: {e}")
        # Fallback to manual calculation
        return calculate_manual_sighash(tx, input_index, scriptPubKey, sighash_type)

def calculate_manual_sighash(tx: CTransaction, input_index: int, scriptPubKey: CScript, 
                           sighash_type: int) -> bytes:
    """Manual sighash calculation as fallback"""
    # Create a copy of the transaction
    tx_copy = CTransaction(tx.vin[:], tx.vout[:], tx.nLockTime, tx.nVersion)
    
    # Clear all input scripts
    for i in range(len(tx_copy.vin)):
        tx_copy.vin[i] = CTxIn(tx_copy.vin[i].prevout, CScript(), tx_copy.vin[i].nSequence)
    
    # Set the script for the input being signed
    tx_copy.vin[input_index] = CTxIn(
        tx_copy.vin[input_index].prevout, 
        scriptPubKey, 
        tx_copy.vin[input_index].nSequence
    )
    
    # Handle different sighash types
    if sighash_type & 0x1f == SIGHASH_NONE:
        tx_copy.vout = []
        for i in range(len(tx_copy.vin)):
            if i != input_index:
                tx_copy.vin[i] = CTxIn(tx_copy.vin[i].prevout, tx_copy.vin[i].scriptSig, 0)
    
    elif sighash_type & 0x1f == SIGHASH_SINGLE:
        if input_index >= len(tx_copy.vout):
            # Invalid SIGHASH_SINGLE
            return b'\x01' + b'\x00' * 31
        
        tx_copy.vout = tx_copy.vout[:input_index + 1]
        for i in range(input_index):
            tx_copy.vout[i] = CTxOut(-1, CScript())
        
        for i in range(len(tx_copy.vin)):
            if i != input_index:
                tx_copy.vin[i] = CTxIn(tx_copy.vin[i].prevout, tx_copy.vin[i].scriptSig, 0)
    
    if sighash_type & SIGHASH_ANYONECANPAY:
        tx_copy.vin = [tx_copy.vin[input_index]]
    
    # Serialize and hash
    tx_bytes = tx_copy.serialize()
    tx_bytes += struct.pack('<I', sighash_type)
    
    return Hash(tx_bytes)

def calculate_segwit_sighash(tx: CTransaction, input_index: int, scriptCode: CScript, 
                           amount: int, sighash_type: int) -> bytes:
    """Calculate BIP 143 segwit signature hash"""
    
    def get_prevouts_hash():
        if not (sighash_type & SIGHASH_ANYONECANPAY):
            prevouts = b''
            for txin in tx.vin:
                prevouts += txin.prevout.serialize()
            return Hash(prevouts)
        return b'\x00' * 32
    
    def get_sequence_hash():
        if (not (sighash_type & SIGHASH_ANYONECANPAY) and 
            (sighash_type & 0x1f) != SIGHASH_SINGLE and 
            (sighash_type & 0x1f) != SIGHASH_NONE):
            sequences = b''
            for txin in tx.vin:
                sequences += struct.pack('<I', txin.nSequence)
            return Hash(sequences)
        return b'\x00' * 32
    
    def get_outputs_hash():
        if ((sighash_type & 0x1f) != SIGHASH_SINGLE and (sighash_type & 0x1f) != SIGHASH_NONE):
            outputs = b''
            for txout in tx.vout:
                outputs += txout.serialize()
            return Hash(outputs)
        elif ((sighash_type & 0x1f) == SIGHASH_SINGLE and input_index < len(tx.vout)):
            return Hash(tx.vout[input_index].serialize())
        return b'\x00' * 32
    
    # BIP 143 sighash calculation
    ss = BytesIO()
    ss.write(struct.pack('<I', tx.nVersion))
    ss.write(get_prevouts_hash())
    ss.write(get_sequence_hash())
    ss.write(tx.vin[input_index].prevout.serialize())
    ss.write(scriptCode.serialize())
    ss.write(struct.pack('<Q', amount))
    ss.write(struct.pack('<I', tx.vin[input_index].nSequence))
    ss.write(get_outputs_hash())
    ss.write(struct.pack('<I', tx.nLockTime))
    ss.write(struct.pack('<I', sighash_type))
    
    return Hash(ss.getvalue())

def calculate_taproot_sighash(tx: CTransaction, input_index: int, prevouts: List[CTxOut],
                            sighash_type: int = 0, script_path: bool = False,
                            script: bytes = None, leaf_version: int = None,
                            annex: bytes = None) -> bytes:
    """Calculate BIP 341 taproot signature hash"""
    
    # BIP 341 tagged hash
    def tagged_hash(tag: bytes, data: bytes) -> bytes:
        tag_hash = hashlib.sha256(tag).digest()
        return hashlib.sha256(tag_hash + tag_hash + data).digest()
    
    # Common signature message
    epoch = b'\x00'
    sighash_byte = bytes([sighash_type])
    
    ss = BytesIO()
    ss.write(epoch)
    ss.write(sighash_byte)
    ss.write(struct.pack('<I', tx.nVersion))
    ss.write(struct.pack('<I', tx.nLockTime))
    
    # Inputs
    if sighash_type & SIGHASH_ANYONECANPAY:
        ss.write(struct.pack('<B', 1))  # Single input
        ss.write(tx.vin[input_index].prevout.serialize())
        ss.write(struct.pack('<Q', prevouts[input_index].nValue))
        ss.write(prevouts[input_index].scriptPubKey.serialize())
        ss.write(struct.pack('<I', tx.vin[input_index].nSequence))
    else:
        ss.write(struct.pack('<B', len(tx.vin)))
        for i, txin in enumerate(tx.vin):
            ss.write(txin.prevout.serialize())
            ss.write(struct.pack('<Q', prevouts[i].nValue))
            ss.write(prevouts[i].scriptPubKey.serialize())
            ss.write(struct.pack('<I', txin.nSequence))
    
    # Outputs
    sighash_masked = sighash_type & 0x1f
    if sighash_masked == SIGHASH_NONE:
        ss.write(struct.pack('<B', 0))
    elif sighash_masked == SIGHASH_SINGLE:
        if input_index < len(tx.vout):
            ss.write(struct.pack('<B', 1))
            ss.write(struct.pack('<Q', tx.vout[input_index].nValue))
            ss.write(tx.vout[input_index].scriptPubKey.serialize())
        else:
            ss.write(struct.pack('<B', 0))
    else:  # SIGHASH_ALL or SIGHASH_DEFAULT
        ss.write(struct.pack('<B', len(tx.vout)))
        for txout in tx.vout:
            ss.write(struct.pack('<Q', txout.nValue))
            ss.write(txout.scriptPubKey.serialize())
    
    # Script path data
    if script_path:
        ss.write(struct.pack('<B', 1))  # spend_type = 1 for script path
        if script and leaf_version is not None:
            leaf_hash = tagged_hash(b"TapLeaf", bytes([leaf_version]) + 
                                  struct.pack('<I', len(script)) + script)
            ss.write(leaf_hash)
        ss.write(struct.pack('<B', input_index))
        if annex:
            annex_hash = tagged_hash(b"TapSighash/Annex", annex)
            ss.write(annex_hash)
    else:
        ss.write(struct.pack('<B', 0))  # spend_type = 0 for key path
    
    return tagged_hash(b"TapSighash", ss.getvalue())

def parse_transaction_signatures(tx_hex: str, prev_txs_hex: List[str] = None,
                               prev_outputs: List[Dict] = None) -> List[Dict[str, Any]]:
    """
    Complete signature parser for all Bitcoin transaction types using python-bitcoinlib.
    
    Args:
        tx_hex: Raw transaction in hex format
        prev_txs_hex: List of previous transaction hex strings (for legacy sighash)
        prev_outputs: List of dicts with 'value' and 'scriptPubKey' for each input
    
    Returns:
        List of signature information dictionaries
    """
    try:
        tx_bytes = bytes.fromhex(tx_hex)
        tx = CTransaction.deserialize(tx_bytes)
    except Exception as e:
        raise ValueError(f"Invalid transaction hex: {e}")
    
    signatures_info = []
    
    # Parse previous transactions if provided
    prev_txs = {}
    if prev_txs_hex:
        for prev_tx_hex in prev_txs_hex:
            try:
                prev_tx = CTransaction.deserialize(bytes.fromhex(prev_tx_hex))
                prev_txs[prev_tx.GetTxid()] = prev_tx
            except:
                continue
    
    # Process each input
    for input_idx, txin in enumerate(tx.vin):
        try:
            # Get previous output info
            prev_tx = prev_txs.get(txin.prevout.hash) if prev_txs else None
            
            if prev_tx and txin.prevout.n < len(prev_tx.vout):
                scriptPubKey = prev_tx.vout[txin.prevout.n].scriptPubKey
                prev_amount = prev_tx.vout[txin.prevout.n].nValue
            elif prev_outputs and input_idx < len(prev_outputs):
                # Use provided output info
                output_info = prev_outputs[input_idx]
                scriptPubKey = CScript(bytes.fromhex(output_info['scriptPubKey']))
                prev_amount = output_info['value']
            else:
                print(f"Warning: Missing previous output info for input {input_idx}")
                continue
            
            # Get witness data
            witness_data = []
            if hasattr(tx, 'wit') and tx.wit and input_idx < len(tx.wit.vtxinwit):
                witness_stack = tx.wit.vtxinwit[input_idx].scriptWitness.stack
                witness_data = [bytes(item) for item in witness_stack]
            
            # Detect script type
            script_type = detect_script_type(scriptPubKey, txin.scriptSig, witness_data)
            
            # Extract signatures and public keys
            sig_pubkey_pairs = extract_signatures_and_pubkeys(
                txin.scriptSig, witness_data, script_type
            )
            
            # Process each signature
            for sig_idx, (sig_bytes, pubkey_bytes) in enumerate(sig_pubkey_pairs):
                try:
                    signature_info = {
                        'input_index': input_idx,
                        'signature_index': sig_idx,
                        'script_type': script_type.value,
                        'pubkey': pubkey_bytes.hex() if pubkey_bytes else None,
                        'signature_hex': sig_bytes.hex(),
                    }
                    
                    if script_type == ScriptType.P2TR:
                        # Taproot Schnorr signatures
                        if len(sig_bytes) == 65:
                            sighash_type = sig_bytes[64]
                            raw_sig = sig_bytes[:64]
                        elif len(sig_bytes) == 64:
                            sighash_type = 0  # SIGHASH_DEFAULT
                            raw_sig = sig_bytes
                        else:
                            print(f"Invalid taproot signature length: {len(sig_bytes)}")
                            continue
                        
                        # Schnorr signature: R (32 bytes) + s (32 bytes)
                        r = int.from_bytes(raw_sig[:32], byteorder='big')
                        s = int.from_bytes(raw_sig[32:], byteorder='big')
                        
                        # Calculate taproot sighash
                        if prev_outputs:
                            prev_outs = [CTxOut(out['value'], CScript(bytes.fromhex(out['scriptPubKey']))) 
                                        for out in prev_outputs]
                            z = calculate_taproot_sighash(tx, input_idx, prev_outs, sighash_type)
                        else:
                            print(f"Warning: Cannot calculate taproot sighash without prev_outputs")
                            z = b'\x00' * 32
                        
                        signature_info.update({
                            'r': r,
                            's': s,
                            'z': z.hex(),
                            'sighash_type': sighash_type,
                            'signature_type': 'schnorr'
                        })
                    
                    else:
                        # ECDSA signatures (legacy and segwit)
                        if len(sig_bytes) < 2:
                            continue
                        
                        sighash_type = sig_bytes[-1]
                        raw_sig = sig_bytes[:-1]
                        
                        # Parse DER signature
                        try:
                            r, s = parse_der_signature(raw_sig)
                        except ValueError as e:
                            print(f"Failed to parse DER signature: {e}")
                            continue
                        
                        # Calculate appropriate sighash
                        if script_type in [ScriptType.P2WPKH, ScriptType.P2WSH]:
                            # Segwit sighash (BIP 143)
                            if script_type == ScriptType.P2WPKH:
                                # For P2WPKH, scriptCode is standard P2PKH script
                                pubkey_hash = bytes(scriptPubKey)[2:22]  # Extract hash160
                                scriptCode = CScript([OP_DUP, OP_HASH160, pubkey_hash, 
                                                    OP_EQUALVERIFY, OP_CHECKSIG])
                            else:  # P2WSH
                                # For P2WSH, scriptCode is the witness script
                                if witness_data:
                                    scriptCode = CScript(witness_data[-1])
                                else:
                                    print(f"Missing witness script for P2WSH")
                                    continue
                            
                            z = calculate_segwit_sighash(tx, input_idx, scriptCode, 
                                                       prev_amount, sighash_type)
                        
                        elif script_type == ScriptType.P2SH and witness_data:
                            # P2SH-wrapped segwit
                            redeem_script_ops = list(txin.scriptSig)
                            if redeem_script_ops:
                                redeem_script = CScript(redeem_script_ops[-1])
                                inner_type = detect_script_type(redeem_script)
                                
                                if inner_type == ScriptType.P2WPKH:
                                    # P2WPKH-in-P2SH
                                    pubkey_hash = bytes(redeem_script)[2:22]
                                    scriptCode = CScript([OP_DUP, OP_HASH160, pubkey_hash, 
                                                        OP_EQUALVERIFY, OP_CHECKSIG])
                                    z = calculate_segwit_sighash(tx, input_idx, scriptCode, 
                                                               prev_amount, sighash_type)
                                elif inner_type == ScriptType.P2WSH:
                                    # P2WSH-in-P2SH
                                    if witness_data:
                                        scriptCode = CScript(witness_data[-1])
                                        z = calculate_segwit_sighash(tx, input_idx, scriptCode, 
                                                                   prev_amount, sighash_type)
                                    else:
                                        print(f"Missing witness script for P2WSH-in-P2SH")
                                        continue
                                else:
                                    # Regular P2SH (non-segwit)
                                    z = calculate_legacy_sighash(tx, input_idx, redeem_script, sighash_type)