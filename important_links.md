# Test Transactions for State Update Squashing

## Starknet 0.13.2
- **Transaction:** [0x46fbbb4000063c7409f6b10de283d76cfb7c8f5585304697625e8b184022e644](https://sepolia.etherscan.io/tx/0x46fbbb4000063c7409f6b10de283d76cfb7c8f5585304697625e8b184022e644)
- **Type:** Multiple blocks ➝ Single blob
- **Starknet-Sepolia Block Range:** 219914-219938

## Starknet 0.13.3
### Example 1: Multi-Blocks, Single Blob
- **Transaction:** [0x76706ee4a0a9e1ed5d27562a28a620e66139311c76ac2e78c3187b3f6b1324db](https://sepolia.etherscan.io/tx/0x76706ee4a0a9e1ed5d27562a28a620e66139311c76ac2e78c3187b3f6b1324db)
- **Starknet-Sepolia Block Range:** 309144-309145 (2 blocks)

### Example 2: Multi-Blocks, Multi-Blobs
- **Transaction:** [0x089499bde446a1d1730e7f684eac299b3f2e07c8c86e1d16ee06931c1e1fc465](https://sepolia.etherscan.io/tx/0x089499bde446a1d1730e7f684eac299b3f2e07c8c86e1d16ee06931c1e1fc465)
- **Starknet-Sepolia Block Range:** 309146-309401 (256 blocks)


## Starknet 0.13.4

the flow: state-update -> merge multiple -> do statefull compression -> change to blob data -> do stateless compression -> fft -> final

what's we gonna do?

state-update -> merge multiple -> do statefull compression -> change to blob data -> dataJSON

blob -> ifft -> stateless decompression -> dataJSON

and we match both in the end

### Example 1: Multi-blocks and multi-blobs
- **Transaction:** [0xb59bd757065a4ac72a0795beb886c167631f136f71915552794007ed8c22f374](https://sepolia.etherscan.io/tx/0xb59bd757065a4ac72a0795beb886c167631f136f71915552794007ed8c22f374)
- **Starknet-sepolia block range:** 551629-552012 (384 blocks)

**IMP:** do ifft on individual blocks and then merge the output and then do stateless decompression
