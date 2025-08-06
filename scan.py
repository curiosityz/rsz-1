#!/usr/bin/env python3
from whole_tool import ECDSAAffineAttack

# Initialize with Chainstack
attack = ECDSAAffineAttack(
    chainstack_url="https://bitcoin-mainnet.core.chainstack.com/8995629f764c176fb4e05bdf4ab84277"
)

# Analyze blocks for signatures
result = attack.analyze_blockchain_signatures(
    block_range=(750000, 750100),  # Start with 100 blocks
    max_blocks=100,
    search_affine_relationships=True
)

# Export results
attack.export_analysis_results(
    result=result,
    filename="analysis_results.json",
    include_signatures=True
)
