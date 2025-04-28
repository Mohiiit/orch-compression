# Orch-Compression

A utility for compressing, processing, and managing Starknet state updates, optimizing them for data availability through blobs.

## Overview

Orch-Compression is designed to efficiently handle Starknet state updates by:
1. Compressing state updates to reduce size
2. Converting state updates to optimized blob format for data availability
3. Enabling recovery of original data from compressed blobs
4. Fetching and managing state updates directly from Starknet

## Output Directory Structure

All commands follow a standardized output directory structure:
```
output/
  ├── compress/
  │   └── compressed_state_updates.json
  ├── blob/
  │   └── blob_data.dat
  ├── recover/
  │   ├── post_process_blob_<file_name>.txt
  │   └── squashed_state_diff_from_blob_<file_name>.json
  ├── multi-blob/
  │   ├── blob_0.dat
  │   ├── blob_1.dat
  │   └── ...
  ├── fetch-update/
  │   ├── state_update_<block_number>.json
  │   └── ...
  ├── merge-json/
  │   └── merged_state_updates.json
  ├── json-to-blob/
  │   └── blob_from_json.dat
  └── blob-to-dataJson/
      └── data_json_output.json
```

This structure ensures that outputs from different steps are organized in their own directories, preventing file conflicts and making it easier to manage multiple operations.

## Command Flows

### 1. Compress Command

**Usage**: `orch-compression compress <input_dir> <output_file>`

**Data Flow**:
1. **Input**: Directory containing state update JSON files named `<name>_<block_number>.json`
   - Each file contains Starknet state updates with contract addresses, storage updates, and class declarations
2. **Processing**:
   - Files are sorted by block number to ensure chronological processing
   - For each file, state updates are parsed from JSON
   - Updates for the same contract addresses are merged
   - For each address, the latest nonce and storage values are kept
   - Repeated storage keys are optimized to retain only the most recent value
3. **Output**: A single JSON file at `output/compress/<output_file>` containing the compressed state updates
   - The output maintains the same structure but with optimized and deduplicated data

This command is useful for creating an optimized representation of state updates across multiple blocks.

### 2. Blob Command

**Usage**: `orch-compression blob <input_file> <output_file>`

**Data Flow**:
1. **Input**: A file containing state updates in JSON format
   - Can be the output of the `compress` command or any compatible state update format
2. **Processing**:
   - Parses the state updates into blob-compatible data
   - Organizes contract updates by address
   - Encodes storage updates as data words optimized for blob storage
   - Processes the data into a blob-friendly format
   - Performs necessary encoding and transformation to create a blob
3. **Output**: A binary blob file at `output/blob/<output_file>` containing the encoded state update data
   - The blob format is optimized for data availability protocols

This command converts state update data into a blob format suitable for data availability protocols like EIP-4844.

### 3. Recover Command

**Usage**: `orch-compression recover <blob_file> <output_file>`

**Data Flow**:
1. **Input**: A blob file containing compressed state update data
   - Typically the output of the `blob` command
2. **Processing**:
   - Reads the blob file as a hex string
   - Converts the hex string to a byte array
   - Transforms the bytes back to BigUint values
   - Processes the blob data to recover the original state updates
   - Parses the recovered data into state diffs
3. **Output**: Files in the `output/recover/` directory:
   - `post_process_blob_<file_name>.txt`: Intermediate processed blob data
   - `squashed_state_diff_from_blob_<file_name>.json`: Recovered state update data in JSON format

This command allows for reconstructing the original state update data from a compressed blob.

### 4. Multi-Blob Command

**Usage**: `orch-compression multi-blob <input_dir> <output_dir>`

**Data Flow**:
1. **Input**: Directory containing multiple state update files
   - Each file can be in JSON format with state update data
2. **Processing**:
   - Processes each file individually:
     - Parses the file into blob-compatible data
     - Converts state updates to data structures for blob creation
     - Compresses the state updates
     - Creates individual blobs for each file
   - After processing all files, further optimizes and compresses the collection of blobs
3. **Output**: Multiple blob files in the `output/multi-blob/` directory named `blob_<index>.dat`
   - Each blob contains optimized state update data

This command is useful for batch processing multiple state updates into optimized blobs.

### 5. Fetch-Update Command

**Usage**: `orch-compression fetch-update <output_dir> [start_block] [end_block]`

**Data Flow**:
1. **Input**: 
   - Output directory to store fetched state updates
   - Optional start and end block numbers
   - RPC URL (from .env or default)
2. **Processing**:
   - Connects to a Starknet node using the JSON-RPC API
   - If block range specified:
     - Fetches state updates for each block in the range
   - If no range specified:
     - Fetches only the latest state update
   - Handles errors for individual blocks without failing the entire process
3. **Output**: JSON files in the `output/fetch-update/` directory:
   - If range specified: `state_update_<block_number>.json` for each block
   - If no range: `state_update_latest.json`

This command allows direct fetching of state updates from a Starknet node without requiring manual downloads.

### 6. Merge-JSON Command

**Usage**: `orch-compression merge-json <input_dir> <output_file>`

**Data Flow**:
1. **Input**: Directory containing state update JSON files named `<name>_<block_number>.json`
   - Similar to the compress command but with different output format
2. **Processing**:
   - Files are sorted by block number to ensure chronological processing
   - State updates from all files are merged
   - The merging logic combines updates while maintaining data integrity
   - Unlike compress, focuses on JSON representation rather than blob preparation
   - Storage entries with a value of 0x0 are excluded from the final output
3. **Output**: A single JSON file at `output/merge-json/<output_file>` containing the merged state updates
   - The output maintains a pure JSON format suitable for other tools

This command is useful for creating a comprehensive state update JSON without compression optimizations.

### 7. JSON-to-Blob Command

**Usage**: `orch-compression json-to-blob <input_file> <output_file> [block_number]`

**Data Flow**:
1. **Input**: 
   - JSON file containing state update data
   - Optional block number for reference
2. **Processing**:
   - Reads the JSON file as a string
   - Converts the JSON directly to blob data without intermediate processing
   - Uses the block number as reference if provided
3. **Output**: A file at `output/json-to-blob/<output_file>` containing the BigUint values representing the blob data
   - This format is ready for further processing or submission

This command provides a direct path from JSON state updates to blob data without intermediate steps.

### 8. Blob-to-DataJson Command

**Usage**: `orch-compression blob-to-dataJson <input_file> <output_file>`

**Data Flow**:
1. **Input**: A file containing BigUint values representing blob data
   - Typically the output of intermediate processing steps or a BigUint representation of blob data
2. **Processing**:
   - Reads the BigUint values from the input file
   - Parses the BigUint data to extract state updates, converting it to DataJson format
   - Organizes the data into contract updates, storage updates, and class declarations
3. **Output**: A JSON file at `output/blob-to-dataJson/<output_file>` containing the parsed data in DataJson format
   - The output includes structured state update information that can be easily processed by other tools

This command is useful for converting raw BigUint data directly to a structured DataJson format without going through the full recovery process.

### 9. Stateless-Decompression Command

**Usage**: `orch-compression stateless-decompression <input_file> <output_file>`

**Data Flow**:
1. **Input**: A file containing BigUint values representing compressed data
   - The input file should contain BigUint values that were previously compressed using stateless compression
2. **Processing**:
   - Reads the BigUint values from the input file
   - Converts the BigUint values to Felt array for processing
   - Performs stateless decompression on the Felt array
   - Converts the decompressed Felt array back to BigUint values
3. **Output**: A file at `output/stateless-decompression/<output_file>` containing the decompressed data as BigUint values
   - The output maintains the same BigUint format but contains the decompressed data

This command is useful for recovering the original data from files that were compressed using the stateless compression algorithm. It handles the necessary conversions between BigUint and Felt types while maintaining data integrity throughout the decompression process.

## Key Data Structures

Throughout these flows, several key data structures are manipulated:

1. **ContractUpdate**:
   - `address`: Contract address as BigUint
   - `nonce`: Contract's nonce value
   - `storage_updates`: List of key-value pairs for storage
   - `new_class_hash`: Optional new class hash if the contract was upgraded

2. **StorageUpdate**:
   - `key`: Storage key as BigUint
   - `value`: Storage value as BigUint

3. **ClassDeclaration**:
   - `class_hash`: Hash of the class as BigUint
   - `compiled_class_hash`: Compiled class hash as BigUint

4. **DataJson**:
   - Container for state updates and class declarations
   - Includes sizes and collections of both types

## Dependencies

The utility relies on several Rust libraries:
- `starknet`: For interacting with Starknet nodes
- `num-bigint`: For handling large integers common in blockchain data
- `serde`: For JSON serialization/deserialization
- `tokio`: For async operations
- `dotenv`: For environment configuration

## Environment Configuration

The utility can be configured using a `.env` file with the following variables:
- `STARKNET_RPC_URL`: URL of the Starknet RPC endpoint (defaults to Nethermind's public endpoint if not specified)

## Directory Setup

Before running any commands, ensure the output directory structure exists:

```bash
mkdir -p output/compress output/blob output/recover output/multi-blob output/fetch-update output/merge-json output/json-to-blob output/blob-to-dataJson
```

This will create all necessary directories to follow the standardized output path convention. 