import requests
import json

block_hash = "0000000000000000000592a974b1b9f087cb77628bb4a097d5c2c11b3476a58e"
url = "https://bitcoin-mainnet.core.chainstack.com/8995629f764c176fb4e05bdf4ab84277"
headers = {'Content-Type': 'application/json'}
data = {
    "jsonrpc": "2.0",
    "method": "getblock",
    "params": [block_hash, 2],
    "id": 1
}

response = requests.post(url, headers=headers, data=json.dumps(data))
block = response.json()

if 'result' in block:
    with open('block_750000.json', 'w') as f:
        json.dump(block['result'], f, indent=2)
        print("Block data saved to block_750000.json")
else:
    print("Error:", block.get('error', 'Unknown error'))
