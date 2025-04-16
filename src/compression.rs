use crate::models::{ClassDeclaration, ContractUpdate, DataJson, StorageUpdate};
use crate::serde_utils;
use num_bigint::BigUint;
use num_traits::{Num, Zero};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::env;
use eyre::WrapErr;
use starknet::core::types::{
    BlockId, ContractStorageDiffItem, DeclaredClassItem, DeployedContractItem, 
    Felt, NonceUpdate, ReplacedClassItem, StateUpdate, StateDiff, StorageEntry
};
use starknet::providers::{
    jsonrpc::{HttpTransport, JsonRpcClient},
    Provider, Url,
};

// Custom JobError struct for compatibility with the provided code
#[derive(Debug)]
pub enum JobError {
    Other(OtherError),
}

#[derive(Debug)]
pub struct OtherError(pub eyre::Report);

/// Compresses state updates by merging updates for the same contract address
/// and taking only the latest values for each storage key.
/// 
/// # Arguments
/// * `update` - A `DataJson` containing state updates to compress
/// 
/// # Returns
/// A `DataJson` with compressed state updates
pub fn compress_state_updates(update: DataJson) -> DataJson {
    // Maps to track latest state by contract address
    let mut contract_updates_map: HashMap<BigUint, ContractUpdate> = HashMap::new();
    let mut class_declarations: HashSet<(BigUint, BigUint)> = HashSet::new();
    
    // Process class declarations (simply collect all of them)
    for class_decl in update.class_declaration {
        class_declarations.insert((class_decl.class_hash.clone(), class_decl.compiled_class_hash.clone()));
    }
    
    // Process contract updates
    for contract_update in update.state_update {
        let address = contract_update.address.clone();
        
        // If we already have an update for this contract, merge them
        if let Some(existing_update) = contract_updates_map.get_mut(&address) {
            // Update nonce (always take the latest)
            existing_update.nonce = contract_update.nonce;
            
            // Update class hash if present
            if contract_update.new_class_hash.is_some() {
                existing_update.new_class_hash = contract_update.new_class_hash;
            }
            
            // Merge storage updates (latest value per key wins)
            let mut storage_map: HashMap<BigUint, BigUint> = existing_update
                .storage_updates
                .iter()
                .map(|su| (su.key.clone(), su.value.clone()))
                .collect();
            
            // Apply the new storage updates on top
            for storage_update in contract_update.storage_updates {
                storage_map.insert(storage_update.key, storage_update.value);
            }
            
            // Rebuild the storage updates vector
            existing_update.storage_updates = storage_map
                .into_iter()
                .map(|(key, value)| StorageUpdate { key, value })
                .collect();
            
            // Update the count
            existing_update.number_of_storage_updates = existing_update.storage_updates.len() as u64;
        } else {
            // This is a new contract address, add it directly
            contract_updates_map.insert(address, contract_update);
        }
    }
    
    // Convert back to vectors
    let state_update: Vec<ContractUpdate> = contract_updates_map.into_values().collect();
    let class_declaration: Vec<crate::models::ClassDeclaration> = class_declarations
        .into_iter()
        .map(|(class_hash, compiled_class_hash)| crate::models::ClassDeclaration {
            class_hash,
            compiled_class_hash,
        })
        .collect();
    
    DataJson {
        state_update_size: state_update.len() as u64,
        state_update,
        class_declaration_size: class_declaration.len() as u64,
        class_declaration,
    }
}

/// Creates a DA word with information about a contract
/// 
/// # Arguments
/// * `class_flag` - Indicates if a new class hash is present
/// * `nonce_change` - Optional nonce value as a Felt
/// * `num_changes` - Number of storage updates
/// 
/// # Returns
/// A `Felt` representing the encoded DA word
pub fn da_word(class_flag: bool, nonce_change: Option<Felt>, num_changes: u64) -> color_eyre::Result<Felt> {
    // padding of 127 bits
    let mut binary_string = "0".repeat(127);

    // class flag of one bit
    if class_flag {
        binary_string += "1"
    } else {
        binary_string += "0"
    }

    // checking for nonce here
    if let Some(new_nonce) = nonce_change {
        let bytes: [u8; 32] = new_nonce.to_bytes_be();
        let biguint = BigUint::from_bytes_be(&bytes);
        let binary_string_local = format!("{:b}", biguint);
        let padded_binary_string = format!("{:0>64}", binary_string_local);
        binary_string += &padded_binary_string;
    } else {
        let binary_string_local = "0".repeat(64);
        binary_string += &binary_string_local;
    }

    let binary_representation = format!("{:b}", num_changes);
    let padded_binary_string = format!("{:0>64}", binary_representation);
    binary_string += &padded_binary_string;

    let biguint = BigUint::from_str_radix(binary_string.as_str(), 2)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to convert binary string to BigUint: {}", e))?;

    // Now convert the BigUint to a decimal string
    let decimal_string = biguint.to_str_radix(10);

    Felt::from_dec_str(&decimal_string)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to convert decimal string to FieldElement: {}", e))
}

/// Encodes information about a contract into a DA word
/// 
/// # Arguments
/// * `class_flag` - Indicates if a new class hash is present
/// * `nonce` - The nonce value
/// * `num_changes` - Number of storage updates
/// 
/// # Returns
/// A `BigUint` representing the encoded DA word
pub fn encode_da_word(class_flag: bool, nonce: u64, num_changes: u64) -> BigUint {
    let mut binary_string = "0".repeat(127);

    // Set class flag bit (bit 127)
    if class_flag {
        binary_string += "1"
    } else {
        binary_string += "0"
    }

    // Add nonce (64 bits from 128-191)
    let nonce_binary = format!("{:064b}", nonce);
    binary_string += &nonce_binary;

    // Add number of changes (64 bits from 192-255)
    let num_changes_binary = format!("{:064b}", num_changes);
    binary_string += &num_changes_binary;

    // Convert binary string to BigUint
    BigUint::parse_bytes(binary_string.as_bytes(), 2).expect("Failed to parse binary string")
}

/// Decodes a DA word to extract contract information
/// 
/// # Arguments
/// * `word` - The `BigUint` DA word to decode
/// 
/// # Returns
/// A tuple containing (class_flag, nonce, num_changes)
pub fn decode_da_word(word: &BigUint) -> (bool, u64, u64) {
    let binary_string = format!("{:b}", word);
    let bitstring = format!("{:0>256}", binary_string);
    
    // Extract class flag (bit 127)
    let class_flag = &bitstring[127..128] == "1";
    
    // Extract nonce (bits 128-191)
    let nonce_bits = &bitstring[128..192];
    let nonce = u64::from_str_radix(nonce_bits, 2)
        .expect("Invalid binary string for nonce");
    
    // Extract number of changes (bits 192-255)
    let num_changes_bits = &bitstring[192..256];
    let num_changes = u64::from_str_radix(num_changes_bits, 2)
        .expect("Invalid binary string for number of changes");
    
    (class_flag, nonce, num_changes)
}

/// Helps to find state updates that match a key pattern
/// Useful for identifying related state changes
/// 
/// # Arguments
/// * `data` - The `DataJson` to search through
/// * `pattern` - A pattern to match against storage keys
/// 
/// # Returns
/// A vector of matching storage updates
pub fn find_key_pattern_matches<'a>(data: &'a DataJson, pattern: &BigUint) -> Vec<(&'a ContractUpdate, &'a StorageUpdate)> {
    let mut matches = Vec::new();
    
    for contract_update in &data.state_update {
        for storage_update in &contract_update.storage_updates {
            // A simple matching logic - can be enhanced for more complex patterns
            if &storage_update.key % pattern == BigUint::zero() {
                matches.push((contract_update, storage_update));
            }
        }
    }
    
    matches
}

/// Converts a field element representation to BigUint
/// 
/// # Arguments
/// * `bytes` - Byte array representation of a field element
/// 
/// # Returns
/// A `BigUint` representation
pub fn field_element_to_biguint(bytes: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// Converts a BigUint to a 32-byte field element representation
/// 
/// # Arguments
/// * `value` - The BigUint to convert
/// 
/// # Returns
/// A byte array representing the field element
pub fn biguint_to_field_element(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut result = [0u8; 32];
    
    // Copy bytes, padding with zeros if needed
    if bytes.len() <= 32 {
        let start_idx = 32 - bytes.len();
        result[start_idx..].copy_from_slice(&bytes);
    } else {
        // Truncate if bigger than 32 bytes (shouldn't happen with valid field elements)
        result.copy_from_slice(&bytes[bytes.len() - 32..]);
    }
    
    result
}

/// Merges multiple state updates from different files
/// 
/// # Arguments
/// * `file_paths` - A vector of file paths and their associated block numbers
/// 
/// # Returns
/// A single `DataJson` with all state updates merged
pub fn merge_state_update_files(file_paths: Vec<(PathBuf, u64)>) -> color_eyre::Result<DataJson> {
    // Maps to track latest state by contract address
    let mut contract_updates_map: HashMap<BigUint, ContractUpdate> = HashMap::new();
    let mut class_declarations: HashSet<(BigUint, BigUint)> = HashSet::new();
    
    // Process files in order of block number
    for (file_path, block_num) in file_paths {
        println!("Processing file: {:?} (block {})", file_path, block_num);
        
        // Read and parse file
        let blob_data = serde_utils::parse_file_to_blob_data(file_path.to_str().unwrap())?;
        let data_json = serde_utils::parse_state_diffs(&blob_data);
        
        // Process class declarations (collect all of them)
        for class_decl in data_json.class_declaration {
            class_declarations.insert((class_decl.class_hash.clone(), class_decl.compiled_class_hash.clone()));
        }
        
        // Process contract updates
        for contract_update in data_json.state_update {
            let address = contract_update.address.clone();
            
            // If we already have an update for this contract, merge them
            if let Some(existing_update) = contract_updates_map.get_mut(&address) {
                merge_contract_updates(existing_update, contract_update);
            } else {
                // This is a new contract address, add it directly
                contract_updates_map.insert(address, contract_update);
            }
        }
    }
    
    // Convert back to vectors
    let state_update: Vec<ContractUpdate> = contract_updates_map.into_values().collect();
    let class_declaration: Vec<ClassDeclaration> = class_declarations
        .into_iter()
        .map(|(class_hash, compiled_class_hash)| ClassDeclaration {
            class_hash,
            compiled_class_hash,
        })
        .collect();
    
    // Create final DataJson
    let final_data = DataJson {
        state_update_size: state_update.len() as u64,
        state_update,
        class_declaration_size: class_declaration.len() as u64,
        class_declaration,
    };
    
    Ok(final_data)
}

/// Merges a newer contract update into an existing one
/// 
/// # Arguments
/// * `existing_update` - The existing contract update to merge into
/// * `new_update` - The newer contract update to merge from
fn merge_contract_updates(existing_update: &mut ContractUpdate, new_update: ContractUpdate) {
    // Update nonce (always take the latest)
    existing_update.nonce = new_update.nonce;
    
    // Update class hash if present
    if new_update.new_class_hash.is_some() {
        existing_update.new_class_hash = new_update.new_class_hash;
    }
    
    // Merge storage updates (latest value per key wins)
    let mut storage_map: HashMap<BigUint, BigUint> = existing_update
        .storage_updates
        .iter()
        .map(|su| (su.key.clone(), su.value.clone()))
        .collect();
    
    // Apply the new storage updates on top (overwriting existing keys)
    for storage_update in new_update.storage_updates {
        storage_map.insert(storage_update.key, storage_update.value);
    }
    
    // Rebuild the storage updates vector
    existing_update.storage_updates = storage_map
        .into_iter()
        .map(|(key, value)| StorageUpdate { key, value })
        .collect();
    
    // Update the count
    existing_update.number_of_storage_updates = existing_update.storage_updates.len() as u64;
}

/// Merges state update files and returns the merged result as a JSON string
/// 
/// # Arguments
/// * `file_paths` - A vector of file paths and their associated block numbers
/// 
/// # Returns
/// A JSON string with all state updates merged
pub fn merge_state_update_files_to_json(file_paths: Vec<(PathBuf, u64)>) -> color_eyre::Result<String> {
    // Maps to track latest state by contract address
    let mut state_updates = Vec::new();
    
    // Process files in order of block number
    for (file_path, block_num) in file_paths {
        println!("Processing file: {:?} (block {})", file_path, block_num);
        
        // Read file and parse as StateUpdate
        let file_content = std::fs::read_to_string(&file_path)?;
        let state_update: StateUpdate = serde_json::from_str(&file_content)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to parse state update file: {}", e))?;
        
        state_updates.push(state_update);
    }
    
    // Merge state updates
    let merged_update = merge_starknet_state_updates(state_updates)?;
    
    // Serialize to JSON string
    let json_string = serde_json::to_string_pretty(&merged_update)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to serialize merged state update: {}", e))?;
    
    Ok(json_string)
}

/// Merges multiple Starknet StateUpdate objects
/// 
/// # Arguments
/// * `updates` - Vector of StateUpdate objects to merge
/// 
/// # Returns
/// A single merged StateUpdate
fn merge_starknet_state_updates(updates: Vec<StateUpdate>) -> color_eyre::Result<StateUpdate> {
    if updates.is_empty() {
        return Err(color_eyre::eyre::eyre!("No state updates to merge"));
    }
    
    // Take the last block hash and number from the last update as our "latest"
    let last_update = updates.last().unwrap();
    let block_hash = last_update.block_hash;
    let new_root = last_update.new_root;
    let old_root = updates.first().unwrap().old_root;
    
    // Create a new StateDiff to hold the merged state
    let mut state_diff = StateDiff {
        storage_diffs: Vec::new(), 
        deployed_contracts: Vec::new(),
        declared_classes: Vec::new(),
        deprecated_declared_classes: Vec::new(),
        nonces: Vec::new(),
        replaced_classes: Vec::new(),
    };
    
    // Maps to efficiently track the latest state
    let mut storage_diffs_map: HashMap<Felt, HashMap<Felt, Felt>> = HashMap::new();
    let mut deployed_contracts_map: HashMap<Felt, Felt> = HashMap::new();
    let mut declared_classes_map: HashMap<Felt, Felt> = HashMap::new();
    let mut nonces_map: HashMap<Felt, Felt> = HashMap::new();
    let mut replaced_classes_map: HashMap<Felt, Felt> = HashMap::new();
    let mut deprecated_classes_set: HashSet<Felt> = HashSet::new();
    
    // Process each update in order
    for update in updates {
        // Process storage diffs
        for contract_diff in update.state_diff.storage_diffs {
            let contract_addr = contract_diff.address;
            let contract_storage_map = storage_diffs_map
                .entry(contract_addr)
                .or_insert_with(HashMap::new);
                
            for entry in contract_diff.storage_entries {
                contract_storage_map.insert(entry.key, entry.value);
            }
        }
        
        // Process deployed contracts
        for item in update.state_diff.deployed_contracts {
            deployed_contracts_map.insert(item.address, item.class_hash);
        }
        
        // Process declared classes
        for item in update.state_diff.declared_classes {
            declared_classes_map.insert(item.class_hash, item.compiled_class_hash);
        }
        
        // Process nonces
        for item in update.state_diff.nonces {
            nonces_map.insert(item.contract_address, item.nonce);
        }
        
        // Process replaced classes
        for item in update.state_diff.replaced_classes {
            replaced_classes_map.insert(item.contract_address, item.class_hash);
        }
        
        // Process deprecated classes
        for class_hash in update.state_diff.deprecated_declared_classes {
            deprecated_classes_set.insert(class_hash);
        }
    }
    
    // Convert maps back to the required StateDiff format
    
    // Storage diffs
    for (contract_addr, storage_map) in storage_diffs_map {
        let storage_entries = storage_map
            .into_iter()
            .map(|(key, value)| StorageEntry { key, value })
            .collect();
            
        let contract_storage_diff = ContractStorageDiffItem {
            address: contract_addr,
            storage_entries,
        };
        
        state_diff.storage_diffs.push(contract_storage_diff);
    }
    
    // Deployed contracts
    state_diff.deployed_contracts = deployed_contracts_map
        .into_iter()
        .map(|(address, class_hash)| DeployedContractItem { address, class_hash })
        .collect();
    
    // Declared classes
    state_diff.declared_classes = declared_classes_map
        .into_iter()
        .map(|(class_hash, compiled_class_hash)| DeclaredClassItem { class_hash, compiled_class_hash })
        .collect();
    
    // Nonces
    state_diff.nonces = nonces_map
        .into_iter()
        .map(|(contract_address, nonce)| NonceUpdate { contract_address, nonce })
        .collect();
    
    // Replaced classes
    state_diff.replaced_classes = replaced_classes_map
        .into_iter()
        .map(|(contract_address, class_hash)| ReplacedClassItem { contract_address, class_hash })
        .collect();
    
    // Deprecated classes
    state_diff.deprecated_declared_classes = deprecated_classes_set.into_iter().collect();
    
    // Create the merged StateUpdate
    let merged_update = StateUpdate {
        block_hash,
        new_root,
        old_root,
        state_diff,
    };
    
    Ok(merged_update)
}

/// Converts a StateUpdate to a vector of Felt values for blob creation
/// 
/// # Arguments
/// * `block_no` - The block number of the state update
/// * `state_update` - The StateUpdate to convert
/// 
/// # Returns
/// A vector of Felt values representing the state update in a format suitable for blob creation
pub async fn state_update_to_blob_data(block_no: u64, state_update: StateUpdate) -> color_eyre::Result<Vec<Felt>> {
    let mut state_diff = state_update.state_diff;

    let rpc_url = env::var("STARKNET_RPC_URL")
    .unwrap_or_else(|_| "https://free-rpc.nethermind.io/sepolia-juno/".to_string());

    println!("Using RPC URL: {}", rpc_url);

    // Create Starknet provider
    let provider = JsonRpcClient::new(HttpTransport::new(
        Url::parse(&rpc_url).map_err(|e| color_eyre::eyre::eyre!("Invalid URL: {}", e))?,
    ));
    
    // Create a vector to hold the blob data
    let mut blob_data: Vec<Felt> = vec![Felt::from(state_diff.storage_diffs.len())];

    // Create maps for easier lookup
    let deployed_contracts: HashMap<Felt, Felt> =
        state_diff.deployed_contracts.into_iter().map(|item| (item.address, item.class_hash)).collect();
    let replaced_classes: HashMap<Felt, Felt> =
        state_diff.replaced_classes.into_iter().map(|item| (item.contract_address, item.class_hash)).collect();
    let mut nonces: HashMap<Felt, Felt> =
        state_diff.nonces.into_iter().map(|item| (item.contract_address, item.nonce)).collect();

    // Sort storage diffs by address for deterministic output
    state_diff.storage_diffs.sort_by_key(|diff| diff.address);

    // Process each storage diff
    for ContractStorageDiffItem { address, mut storage_entries } in state_diff.storage_diffs.into_iter() {
        // Check if there's a class flag (deployed or replaced)
        let class_flag = deployed_contracts.get(&address).or_else(|| replaced_classes.get(&address));

        // Get nonce if it exists
        let mut nonce = nonces.remove(&address);

        if nonce.is_none() && !storage_entries.is_empty() && address != Felt::ONE {
            let get_current_nonce_result = provider
                .get_nonce(BlockId::Number(block_no), address)
                .await
                .wrap_err("Failed to get nonce ".to_string())?;

            nonce = Some(get_current_nonce_result);
        }

        // Create the DA word
        let da_word = da_word(class_flag.is_some(), nonce, storage_entries.len() as u64)?;
        
        // Add address and DA word to blob data
        blob_data.push(address);
        blob_data.push(da_word);

        // If there's a class hash, add it to blob data
        if let Some(class_hash) = class_flag {
            blob_data.push(*class_hash);
        }

        // Sort storage entries by key for deterministic output
        storage_entries.sort_by_key(|entry| entry.key);
        
        // Add storage entries to blob data
        for entry in storage_entries {
            blob_data.push(entry.key);
            blob_data.push(entry.value);
        }
    }
    
    // Add declared classes count
    blob_data.push(Felt::from(state_diff.declared_classes.len()));

    // Sort declared classes by class_hash for deterministic output
    state_diff.declared_classes.sort_by_key(|class| class.class_hash);

    // Process each declared class
    for DeclaredClassItem { class_hash, compiled_class_hash } in state_diff.declared_classes.into_iter() {
        blob_data.push(class_hash);
        blob_data.push(compiled_class_hash);
    }

    // println!("blob_data: {:?}", blob_data);

    Ok(blob_data)
}

/// Converts a JSON state update file to a vector of Felt values for blob creation
/// 
/// # Arguments
/// * `json_file_path` - Path to the JSON file containing a StateUpdate
/// * `block_no` - Block number to use for the state update
/// 
/// # Returns
/// A vector of Felt values representing the state update in a format suitable for blob creation
pub async fn json_to_blob_data(json_file_path: &str, block_no: u64) -> color_eyre::Result<Vec<Felt>> {
    // Read and parse the state update file
    let file_content = std::fs::read_to_string(json_file_path)?;
    let state_update: StateUpdate = serde_json::from_str(&file_content)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse state update file: {}", e))?;
    
    // Convert the state update to blob data
    state_update_to_blob_data(block_no, state_update).await
} 