# How to Use whole_tool.py - ECDSA Affine Nonce Attack Analysis Tool

`whole_tool.py` is a comprehensive tool for analyzing ECDSA signatures for vulnerabilities related to affinely related nonces (where k2 = a*k1 + b). This guide explains how to use it effectively.

## Key Features

- Analyze blockchain transactions for ECDSA signature vulnerabilities
- Test for affine relationships between nonces
- Support for both Ethereum and Bitcoin transactions
- Chainstack integration for real blockchain data analysis
- Ability to generate vulnerable signatures for testing
- Comprehensive error handling and robust implementation

## Prerequisites

1. Python 3.x
2. Required Python packages:
   ```bash
   pip install ecdsa requests python-bitcoinlib
   ```
3. (Optional) Chainstack API access for blockchain analysis

## Basic Usage

### 1. Import and Initialize

```python
from whole_tool import ECDSAAffineAttack

# Basic initialization
attack = ECDSAAffineAttack()

# With Chainstack (for blockchain analysis)
attack = ECDSAAffineAttack(
    chainstack_url="https://your-node.chainstack.com",
    chainstack_api_key="your-api-key"  # Optional
)
```

### 2. Generate Vulnerable Signatures (For Testing)

```python
# Generate signatures with known affine relationship
signatures, private_key = attack.generate_vulnerable_signatures(
    a=2,  # Affine parameter a
    b=1   # Affine parameter b
)
```

### 3. Recover Private Key

```python
# Attempt to recover private key from signatures
result = attack.recover_private_key(
    signatures=signatures,
    a=2,  # Same affine parameters used in generation
    b=1
)

if result.success:
    print(f"Recovered private key: {hex(result.recovered_private_key)}")
```

### 4. Analyze Blockchain Data

```python
# Analyze a range of blocks
result = attack.analyze_blockchain_signatures(
    block_range=(1000000, 1001000),
    max_blocks=1000,
    search_affine_relationships=True
)

# Export results
attack.export_analysis_results(
    result=result,
    filename="analysis_results.json",
    include_signatures=True
)
```

### 5. Analyze Bitcoin Transactions

```python
# Analyze Bitcoin transactions
result = attack.analyze_bitcoin_transactions(
    tx_hex_list=["transaction_hex_1", "transaction_hex_2"],
    prev_outputs_list=None  # Optional previous outputs info
)
```

## Advanced Features

### 1. Running Automated Tests

```python
# Run comprehensive tests
test_results = attack.run_automated_test(
    num_tests=10,
    affine_params_list=[(2,1), (3,5), (7,11)]  # Test different parameters
)
```

### 2. Detailed Signature Analysis

```python
# Analyze specific signatures
analysis = attack.analyze_signatures(signatures_list)
```

### 3. Custom Chainstack Configuration

```python
# Configure Chainstack after initialization
attack.set_chainstack_config(
    node_url="https://new-node.chainstack.com",
    api_key="new-api-key"
)
```

## Error Handling

The tool includes comprehensive error handling:

- Validates all input parameters
- Handles network issues with Chainstack
- Provides detailed error messages
- Includes fallback mechanisms for critical operations

## Best Practices

1. **Testing**:
   - Always start with test signatures before analyzing real data
   - Use `generate_vulnerable_signatures()` to understand the tool
   - Verify recovered keys with `verify_recovery()`

2. **Blockchain Analysis**:
   - Start with small block ranges to validate setup
   - Use progress callbacks for long-running analyses
   - Export results for persistent storage

3. **Performance**:
   - Use appropriate batch sizes for blockchain analysis
   - Consider rate limiting when using Chainstack
   - Monitor memory usage with large datasets

## Example Workflow

1. Set up the environment:
   ```python
   from whole_tool import ECDSAAffineAttack
   attack = ECDSAAffineAttack()
   ```

2. Generate test cases:
   ```python
   sigs, key = attack.generate_vulnerable_signatures(a=2, b=1)
   print(f"Generated test signatures with private key: {hex(key)}")
   ```

3. Test recovery:
   ```python
   result = attack.recover_private_key(sigs, a=2, b=1)
   if attack.verify_recovery(result, key):
       print("Successfully recovered key!")
   ```

4. Analyze real data:
   ```python
   analysis = attack.analyze_blockchain_signatures(
       block_range=(1000000, 1001000),
       search_affine_relationships=True
   )
   attack.export_analysis_results(analysis, "results.json")
   ```

## Troubleshooting

1. If Chainstack connection fails:
   - Verify URL and API key
   - Check network connectivity
   - Ensure proper rate limiting

2. If signature analysis fails:
   - Validate signature components
   - Check for zero values
   - Verify curve parameters

3. If key recovery fails:
   - Confirm affine parameters
   - Verify signature formatting
   - Check for mathematical edge cases

## Additional Resources

- ECDSA specification
- Bitcoin transaction format
- Chainstack API documentation
- Python-bitcoinlib documentation

## Notes

- This tool is for research and educational purposes
- Always handle private keys securely
- Consider rate limits when analyzing blockchain data
- Export and backup important results
