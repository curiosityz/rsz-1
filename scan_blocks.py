#!/usr/bin/env python3
from whole_tool import ECDSAAffineAttack

# Initialize with Chainstack
attack = ECDSAAffineAttack(
    chainstack_url="https://bitcoin-mainnet.core.chainstack.com/8995629f764c176fb4e05bdf4ab84277"
)

# Analyze blockchain data
result = attack.analyze_blockchain_signatures(
    block_range=(750000, 750100),  # Recent blocks with lots of transactions
    max_blocks=100,
    search_affine_relationships=True
)

# Print results
print("\nAnalysis Results:")
print(f"Blocks analyzed: {result.blocks_analyzed}")
print(f"Transactions processed: {result.transactions_processed}")
print(f"Signatures extracted: {result.signatures_extracted}")
print(f"R-value reuse count: {result.r_value_reuse_count}")
print(f"Unique addresses: {result.unique_addresses}")
print(f"Analysis duration: {result.analysis_duration:.2f} seconds")
print(f"Errors: {result.error_count}")

if result.potential_vulnerabilities:
    print("\nPotential Vulnerabilities Found:")
    for vuln in result.potential_vulnerabilities:
        print(f"\nType: {vuln['type']}")
        print(f"Severity: {vuln['severity']}")
        print(f"Description: {vuln['description']}")

# Export detailed results
attack.export_analysis_results(
    result=result,
    filename="analysis_results.json",
    include_signatures=True
)
