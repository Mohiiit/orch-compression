use std::fs;
use std::collections::{HashMap, HashSet};

use crate::models::{ClassDeclaration, ContractUpdate, DataJson, StorageUpdate, CompressedStateUpdate, StateDiff};
use crate::compression;
use crate::stateless_compression;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero, Num};
use serde_json;
use color_eyre::eyre::Result;
use serde::Serialize;
use starknet::core::types::{StateUpdate, Felt};

const BLOB_LEN: usize = 4096;

/// Function to extract bits based on version >= 0.13.3 format
/// # Arguments
/// * `info_word` - The `BigUint` to extract bits from.
/// # Returns
/// A tuple containing:
/// - new_nonce: u64 (0 if nonce unchanged)
/// - number_of_storage_updates: u64 (8 or 64 bits based on n_updates_len)
/// - class_flag: bool (indicates if class was replaced)
fn extract_bits_v2(info_word: &BigUint) -> (u64, u64, bool) {
    // converting the bigUint to binary
    let binary_string = format!("{:b}", info_word);
    // adding padding so that it can be of 256 length
    let bitstring = format!("{:0>256}", binary_string);
    if bitstring.len() != 256 {
        panic!("Input string must be 256 bits long");
    }

    // Reading from right to left (LSB is last bit):
    // - class_flag (1 bit)
    // - n_updates_len (1 bit)
    // - n_updates (8 or 64 bits depending on n_updates_len)
    // - new_nonce (64 bits)

    // Get class_flag (LSB)
    let class_flag = bitstring.chars().nth(255).unwrap() == '1';

    // Get n_updates_len (second bit from right)
    let n_updates_len = bitstring.chars().nth(254).unwrap() == '0';

    // Get number_of_storage_updates based on n_updates_len
    let number_of_storage_updates = if n_updates_len {
        // Use 64 bits for large number of updates
        // Reading 64 bits before the flags (bits 190-253)
        let updates_bits = &bitstring[190..254];
        u64::from_str_radix(updates_bits, 2)
            .expect("Invalid binary string for large storage updates count")
    } else {
        // Use 8 bits for small number of updates
        // Reading 8 bits before the flags (bits 246-253)
        let updates_bits = &bitstring[246..254];
        u64::from_str_radix(updates_bits, 2)
            .expect("Invalid binary string for small storage updates count")
    };

    // Get the new_nonce (64 bits)
    // Position depends on n_updates_len
    let new_nonce_bits = if n_updates_len {
        // If using 64 bits for updates, nonce is at bits 126-189
        &bitstring[126..190]
    } else {
        // If using 8 bits for updates, nonce is at bits 182-245
        &bitstring[182..246]
    };
    let new_nonce = u64::from_str_radix(new_nonce_bits, 2)
        .expect("Invalid binary string for new nonce");

    // Note: new_nonce will be 0 if the nonce is unchanged
    (new_nonce, number_of_storage_updates, class_flag)
}

/// Updated parse_state_diffs function with version support
pub fn parse_state_diffs(data: &[BigUint], version: &str) -> DataJson {
    if data.is_empty() {
        println!("Error: Empty data array");
        return DataJson {
            state_update_size: 0,
            state_update: Vec::new(),
            class_declaration_size: 0,
            class_declaration: Vec::new(),
        };
    }

    // Parse version string to determine which format to use
    let is_new_version = {
        let version_parts: Vec<u32> = version
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        
        if version_parts.len() >= 3 {
            // Compare with 0.13.3
            version_parts[0] > 0 
            || (version_parts[0] == 0 && version_parts[1] > 13)
            || (version_parts[0] == 0 && version_parts[1] == 13 && version_parts[2] >= 3)
        } else {
            false // Default to old version if version string is invalid
        }
    };

    let mut updates = Vec::new();
    let mut i = 0;
    
    // 0th index has the number of contract updates
    let contract_updated_num = match data[i].to_usize() {
        Some(num) => num,
        None => {
            println!("Error: Could not parse number of contract updates");
            return DataJson {
                state_update_size: 0,
                state_update: Vec::new(),
                class_declaration_size: 0,
                class_declaration: Vec::new(),
            };
        }
    };
    i += 1;
    
    // 1st index should have a special address 0x1
    let special_address = &data[i];
    if special_address != &BigUint::from(1u32) {
        println!("Warning: Expected special address 0x1 at index 1, found {}", special_address);
    }
    
    // Process contract updates
    for _ in 0..contract_updated_num {
        if i >= data.len() {
            println!("Warning: Reached end of data while reading contract updates");
            break;
        }

        let mut do_show = false;
        
        let address = data[i].clone();

        if address == BigUint::from_str_radix("239581092100565142154720645091883797094198622446298991221224471056964065863", 10).expect("Invalid address") {
            do_show = true
        }

        if address == BigUint::zero() {
            break;
        }
        i += 1;
        
        if i >= data.len() {
            println!("Warning: Reached end of data or blob length limit");
            break;
        }
        
        let info_word = &data[i];
        let (nonce, number_of_storage_updates, class_flag) = if is_new_version {
            let (new_nonce, storage_updates, class_flag) = extract_bits_v2(info_word);
            if do_show {
                println!("given the right address, here are the new_noce, storage_updates, class_flag: {:?}, {:?}, {:?}", new_nonce, storage_updates, class_flag);
            }
            (new_nonce, storage_updates, class_flag)
        } else {
            let (class_flag, nonce, storage_updates) = extract_bits(info_word);
            (nonce, storage_updates, class_flag)
        };
        i += 1;

        let new_class_hash = if class_flag {
            if i >= data.len() {
                println!("Warning: Reached end of data while reading class hash");
                None
            } else {
                let hash = Some(data[i].clone());
                i += 1;
                hash
            }
        } else {
            None
        };
        
        let mut storage_updates = Vec::new();
        for _ in 0..number_of_storage_updates {
            if i + 1 >= data.len() {
                println!("Warning: Reached end of data or blob length limit while reading storage updates");
                break;
            }
            
            let key = data[i].clone();
            i += 1;
            let value = data[i].clone();
            i += 1;
            
            if key == BigUint::zero() && value == BigUint::zero() {
                break;
            }
            
            storage_updates.push(StorageUpdate { key, value });
        }

        updates.push(ContractUpdate {
            address,
            nonce,
            number_of_storage_updates,
            new_class_hash,
            storage_updates,
        });
    }

    // Process class declarations (remains the same for both versions)
    let declared_classes_len: usize = if i < data.len() {
        data[i].to_usize().unwrap_or(0)
    } else {
        println!("Warning: Reached end of data before reading declared classes length");
        0
    };
    i += 1;
    
    let mut class_declaration_updates = Vec::new();
    for _ in 0..declared_classes_len {
        if i >= data.len() {
            println!("Warning: Reached end of data while reading class declarations");
            break;
        }
        
        let class_hash = data[i].clone();
        if class_hash == BigUint::zero() {
            println!("Warning: Found zero class hash when expecting non-zero");
            break;
        }
        i += 1;
        
        if i >= data.len() {
            println!("Warning: Reached end of data or blob length limit while reading compiled class hash");
            break;
        }
        
        let compiled_class_hash = data[i].clone();
        i += 1;

        class_declaration_updates.push(ClassDeclaration {
            class_hash,
            compiled_class_hash,
        });
    }

    DataJson {
        state_update_size: (contract_updated_num).to_u64().unwrap_or(0),
        state_update: updates,
        class_declaration_size: declared_classes_len.to_u64().unwrap_or(0),
        class_declaration: class_declaration_updates,
    }
}

/// Function to convert a struct to a JSON string.
/// # Arguments
/// * `data` - Any serializable struct.
/// # Returns
/// A JSON string.
pub fn to_json<T: Serialize>(data: T) -> String {
    serde_json::to_string_pretty(&data).unwrap()
}

/// Parses a file into a vector of BigUint values for blob processing
pub fn parse_file_to_blob_data(file_path: &str) -> Result<Vec<BigUint>> {
    let content = fs::read_to_string(file_path)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("Failed to parse file");

    println!("parsed: {:?}", parsed);
    
    // Convert JSON data to a format suitable for blob processing
    // This is a simplified implementation - in a real application,
    // we would parse specific data structures based on the JSON format
    
    let mut result = Vec::new();
    
    if let Some(array) = parsed.as_array() {
        for item in array {
            if let Some(num_str) = item.as_str() {
                if let Ok(num) = num_str.parse::<BigUint>() {
                    result.push(num);
                }
            } else if let Some(num) = item.as_u64() {
                result.push(BigUint::from(num));
            }
        }
    } else if let Some(obj) = parsed.as_object() {
        // Extract values from object and convert to BigUint
        for (_, value) in obj {
            if let Some(num_str) = value.as_str() {
                if let Ok(num) = num_str.parse::<BigUint>() {
                    result.push(num);
                }
            } else if let Some(num) = value.as_u64() {
                result.push(BigUint::from(num));
            }
        }
    }

    println!("result: {:?}", result);
    
    Ok(result)
}

/// Parses state diffs from blob data
pub fn parse_state_diffs_from_blob(blob_data: &Vec<BigUint>) -> Vec<StateDiff> {
    // In a real implementation, this would parse BigUint values into StateDiff structs
    // For now, we'll create a simplified version
    
    let mut diffs = Vec::new();
    
    // Group BigUint values into pairs and create StateDiff objects
    for chunk in blob_data.chunks(2) {
        if chunk.len() == 2 {
            let diff = StateDiff {
                key: chunk[0].to_string(),
                value: chunk[1].to_string(),
            };
            diffs.push(diff);
        }
    }
    
    diffs
}

/// Function to extract class flag, nonce and state_diff length from a `BigUint`.
/// # Arguments
/// * `info_word` - The `BigUint` to extract bits from.
/// # Returns
/// A `bool` representing the class flag.
/// A `u64` representing the nonce.
/// Another`u64` representing the state_diff length
fn extract_bits(info_word: &BigUint) -> (bool, u64, u64) {
    // converting the bigUint to binary
    let binary_string = format!("{:b}", info_word);
    // adding padding so that it can be of 256 length
    let bitstring = format!("{:0>256}", binary_string);
    if bitstring.len() != 256 {
        panic!("Input string must be 256 bits long");
    }
    // getting the class flag, 127th bit is class flag (assuming 0 indexing)
    let class_flag_bit = &bitstring[127..128];
    // getting the nonce, nonce is of 64 bit from 128th bit to 191st bit
    let new_nonce_bits = &bitstring[128..192];
    // getting the state_diff_len, state_diff_len is of 64 bit from 192nd bit to 255th bit
    let num_changes_bits = &bitstring[192..256];

    // converting data to respective type
    let class_flag = class_flag_bit == "1";
    let new_nonce =
        u64::from_str_radix(new_nonce_bits, 2).expect("Invalid binary string for new nonce");
    let num_changes =
        u64::from_str_radix(num_changes_bits, 2).expect("Invalid binary string for num changes");

    (class_flag, new_nonce, num_changes)
}

/// Loads compressed state updates from a JSON file
pub fn load_compressed_updates(file_path: &str) -> Result<Vec<CompressedStateUpdate>> {
    let content = fs::read_to_string(file_path)?;
    let updates: Vec<CompressedStateUpdate> = serde_json::from_str(&content)?;
    Ok(updates)
}

/// Saves compressed state updates to a JSON file
pub fn save_compressed_updates(updates: &Vec<CompressedStateUpdate>, file_path: &str) -> Result<()> {
    let json = to_json(updates);
    fs::write(file_path, json)?;
    Ok(())
}

/// Merges multiple JSON files into a single file
pub fn merge_json_files(input_files: &[&str], output_file: &str) -> Result<()> {
    let mut merged_data = Vec::new();
    
    for file_path in input_files {
        let content = fs::read_to_string(file_path)?;
        let mut updates: Vec<CompressedStateUpdate> = serde_json::from_str(&content)?;
        merged_data.append(&mut updates);
    }
    
    // Deduplicate entries
    merged_data.sort_by(|a, b| a.contract_address.cmp(&b.contract_address));
    merged_data.dedup_by(|a, b| a.key == b.key && a.contract_address == b.contract_address);
    
    save_compressed_updates(&merged_data, output_file)?;
    
    Ok(())
}

/// Extract block number from a filename
/// Format should be <name>_<block_number>.json
pub fn extract_block_number_from_filename(filename: &str) -> u64 {
    if let Some(pos) = filename.rfind('_') {
        let block_part = &filename[pos+1..];
        if let Some(dot_pos) = block_part.find('.') {
            let block_num_str = &block_part[..dot_pos];
            if let Ok(num) = block_num_str.parse::<u64>() {
                return num;
            }
        }
    }
    
    println!("Warning: Could not parse block number from filename: {}", filename);
    0 // Default if parsing fails
}

/// Converts a JSON string containing a StateUpdate to blob data for blob creation
///
/// # Arguments
/// * `json_str` - JSON string containing a StateUpdate
/// * `block_no` - Block number for the state update
/// * `version` - Version of the state update file
///
/// # Returns
/// A Vec<BigUint> suitable for blob creation
pub async fn json_to_blob_data(json_str: &str, block_no: u64, version: &str) -> Result<Vec<BigUint>> {
    // Parse the JSON into a StateUpdate
    let state_update: StateUpdate = serde_json::from_str(json_str)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse JSON as StateUpdate: {}", e))?;
    
    // Convert StateUpdate to Felt vector
    let felts = compression::state_update_to_blob_data(block_no, state_update, version).await?;

    println!("felts size is: {:?}", felts.len());
    
    // Convert Felt vector to BigUint vector
    let biguints = convert_to_biguint(&felts);
    
    Ok(biguints)
}

/// Converts a JSON string containing a StateUpdate to statelessly compressed blob data.
///
/// # Arguments
/// * `json_str` - JSON string containing a StateUpdate
/// * `block_no` - Block number for the state update
///
/// # Returns
/// A Vec<BigUint> representing the compressed blob data.
pub async fn json_to_stateless_compressed_blob_data(json_str: &str, block_no: u64) -> Result<Vec<BigUint>> {
    // Parse the JSON into a StateUpdate
    let state_update: StateUpdate = serde_json::from_str(json_str)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse JSON as StateUpdate: {}", e))?;

    // Convert StateUpdate to Felt vector using the existing compression logic
    let initial_felts = compression::state_update_to_blob_data(block_no, state_update, "0.13.3").await?;
    println!("Initial felts size: {:?}", initial_felts.len());

    // Apply stateless compression
    let compressed_felts = stateless_compression::compress(&initial_felts);
    println!("Statelessly compressed felts size: {:?}", compressed_felts.len());

    // Convert the compressed Felt vector to BigUint vector
    let biguints = convert_to_biguint(&compressed_felts);

    Ok(biguints)
}

pub fn convert_to_biguint(elements: &[Felt]) -> Vec<BigUint> {
    let input_len = elements.len();
    if input_len == 0 {
        return Vec::new(); // Return empty vector for empty input
    }

    // Calculate the required output size: ceil(input_len / 4096.0) * 4096
    // Integer division trick: (input_len + 4095) / 4096 gives the ceiling division result
    let num_blocks = (input_len + 4095) / 4096;
    let output_len = num_blocks * 4096;

    // Initialize the vector with the calculated size, filled with zeros
    let mut biguint_vec = vec![BigUint::zero(); output_len];

    // Iterate over the input elements and place them in the output vector
    for (i, element) in elements.iter().enumerate() { // Remove .take(4096)
        // Convert Felt to [u8; 32]
        let bytes: [u8; 32] = element.to_bytes_be();

        // Convert [u8; 32] to BigUint
        let biguint = BigUint::from_bytes_be(&bytes);

        // Place the converted value at the correct index
        // This automatically leaves remaining spots as zeros
        biguint_vec[i] = biguint;
    }

    biguint_vec
}

/// Parses a JSON string into a DataJson structure
/// 
/// # Arguments
/// * `json_str` - A JSON string representing a DataJson structure
/// 
/// # Returns
/// A Result containing the parsed DataJson structure or an error
pub fn parse_json_to_data_json(json_str: &str) -> Result<DataJson> {
    // First try direct deserialization
    let result = serde_json::from_str::<DataJson>(json_str);
    
    match result {
        Ok(data_json) => Ok(data_json),
        Err(e) => {
            println!("Warning: Standard deserialization failed: {}", e);
            
            // If direct deserialization fails, try parsing as a Value first
            let json_value: serde_json::Value = serde_json::from_str(json_str)?;
            
            let mut state_updates = Vec::new();
            let mut class_declarations = Vec::new();
            
            // Parse state updates
            if let Some(updates) = json_value.get("state_update").and_then(|u| u.as_array()) {
                for update in updates {
                    if let Some(update_obj) = update.as_object() {
                        // Parse address
                        let address = if let Some(addr) = update_obj.get("address") {
                            if let Some(addr_str) = addr.as_str() {
                                addr_str.parse::<BigUint>().unwrap_or(BigUint::zero())
                            } else if let Some(addr_num) = addr.as_u64() {
                                BigUint::from(addr_num)
                            } else {
                                BigUint::zero()
                            }
                        } else {
                            BigUint::zero()
                        };
                        
                        // Parse nonce
                        let nonce = update_obj.get("nonce")
                            .and_then(|n| n.as_u64())
                            .unwrap_or(0);
                        
                        // Parse number of storage updates
                        let number_of_storage_updates = update_obj.get("number_of_storage_updates")
                            .and_then(|n| n.as_u64())
                            .unwrap_or(0);
                        
                        // Parse class hash if present
                        let new_class_hash = update_obj.get("new_class_hash").and_then(|h| {
                            if h.is_null() {
                                None
                            } else if let Some(hash_str) = h.as_str() {
                                Some(hash_str.parse::<BigUint>().unwrap_or(BigUint::zero()))
                            } else if let Some(hash_num) = h.as_u64() {
                                Some(BigUint::from(hash_num))
                            } else {
                                None
                            }
                        });
                        
                        // Parse storage updates
                        let mut storage_updates = Vec::new();
                        if let Some(storage_array) = update_obj.get("storage_updates").and_then(|s| s.as_array()) {
                            for storage in storage_array {
                                if let Some(storage_obj) = storage.as_object() {
                                    // Parse key
                                    let key = if let Some(key_val) = storage_obj.get("key") {
                                        if let Some(key_str) = key_val.as_str() {
                                            key_str.parse::<BigUint>().unwrap_or(BigUint::zero())
                                        } else if let Some(key_num) = key_val.as_u64() {
                                            BigUint::from(key_num)
                                        } else {
                                            BigUint::zero()
                                        }
                                    } else {
                                        BigUint::zero()
                                    };
                                    
                                    // Parse value
                                    let value = if let Some(value_val) = storage_obj.get("value") {
                                        if let Some(value_str) = value_val.as_str() {
                                            value_str.parse::<BigUint>().unwrap_or(BigUint::zero())
                                        } else if let Some(value_num) = value_val.as_u64() {
                                            BigUint::from(value_num)
                                        } else {
                                            BigUint::zero()
                                        }
                                    } else {
                                        BigUint::zero()
                                    };
                                    
                                    storage_updates.push(StorageUpdate { key, value });
                                }
                            }
                        }
                        
                        state_updates.push(ContractUpdate {
                            address,
                            nonce,
                            number_of_storage_updates,
                            new_class_hash,
                            storage_updates,
                        });
                    }
                }
            }
            
            // Parse class declarations
            if let Some(declarations) = json_value.get("class_declaration").and_then(|d| d.as_array()) {
                for decl in declarations {
                    if let Some(decl_obj) = decl.as_object() {
                        // Parse class hash
                        let class_hash = if let Some(hash) = decl_obj.get("class_hash") {
                            if let Some(hash_str) = hash.as_str() {
                                hash_str.parse::<BigUint>().unwrap_or(BigUint::zero())
                            } else if let Some(hash_num) = hash.as_u64() {
                                BigUint::from(hash_num)
                            } else {
                                BigUint::zero()
                            }
                        } else {
                            BigUint::zero()
                        };
                        
                        // Parse compiled class hash
                        let compiled_class_hash = if let Some(hash) = decl_obj.get("compiled_class_hash") {
                            if let Some(hash_str) = hash.as_str() {
                                hash_str.parse::<BigUint>().unwrap_or(BigUint::zero())
                            } else if let Some(hash_num) = hash.as_u64() {
                                BigUint::from(hash_num)
                            } else {
                                BigUint::zero()
                            }
                        } else {
                            BigUint::zero()
                        };
                        
                        class_declarations.push(ClassDeclaration {
                            class_hash,
                            compiled_class_hash,
                        });
                    }
                }
            }
            
            // Get sizes
            let state_update_size = json_value.get("state_update_size")
                .and_then(|s| s.as_u64())
                .unwrap_or(state_updates.len() as u64);
                
            let class_declaration_size = json_value.get("class_declaration_size")
                .and_then(|s| s.as_u64())
                .unwrap_or(class_declarations.len() as u64);
            
            Ok(DataJson {
                state_update_size,
                state_update: state_updates,
                class_declaration_size,
                class_declaration: class_declarations,
            })
        }
    }
}

/// Compares two DataJson structures and outputs a detailed comparison
/// 
/// # Arguments
/// * `data1` - First DataJson structure
/// * `data2` - Second DataJson structure
/// 
/// # Returns
/// A string containing a detailed comparison of the two structures
pub fn compare_data_json(data1: DataJson, data2: DataJson) -> String {
    let mut result = String::new();
    
    // Compare state updates
    result.push_str("# Comparison of State Updates\n\n");
    
    // Create maps for easier lookup
    let mut contract_map1: HashMap<BigUint, &ContractUpdate> = HashMap::new();
    let mut contract_map2: HashMap<BigUint, &ContractUpdate> = HashMap::new();
    
    for update in &data1.state_update {
        contract_map1.insert(update.address.clone(), update);
    }
    
    for update in &data2.state_update {
        contract_map2.insert(update.address.clone(), update);
    }
    
    // Find contracts in data1 but not in data2
    let mut only_in_data1 = Vec::new();
    for (address, update) in &contract_map1 {
        if !contract_map2.contains_key(address) {
            only_in_data1.push(update);
        }
    }
    
    // Find contracts in data2 but not in data1
    let mut only_in_data2 = Vec::new();
    for (address, update) in &contract_map2 {
        if !contract_map1.contains_key(address) {
            only_in_data2.push(update);
        }
    }
    
    // Contracts in both but with differences
    let mut differences = Vec::new();
    for (address, update1) in &contract_map1 {
        if let Some(update2) = contract_map2.get(address) {
            let diff = compare_contract_updates(update1, update2);
            if !diff.is_empty() {
                differences.push((address.clone(), diff));
            }
        }
    }
    
    // Output results
    result.push_str(&format!("State Update Summary:\n"));
    result.push_str(&format!("- Total contracts in first file: {}\n", data1.state_update.len()));
    result.push_str(&format!("- Total contracts in second file: {}\n", data2.state_update.len()));
    result.push_str(&format!("- Contracts only in first file: {}\n", only_in_data1.len()));
    result.push_str(&format!("- Contracts only in second file: {}\n", only_in_data2.len()));
    result.push_str(&format!("- Contracts with differences: {}\n\n", differences.len()));
    
    // Details for contracts only in data1
    if !only_in_data1.is_empty() {
        result.push_str("## Contracts only in first file\n\n");
        for update in only_in_data1 {
            result.push_str(&format!("### Contract Address: {}\n", update.address));
            result.push_str(&format!("- Nonce: {}\n", update.nonce));
            if let Some(class_hash) = &update.new_class_hash {
                result.push_str(&format!("- Class Hash: {}\n", class_hash));
            }
            result.push_str(&format!("- Storage Updates: {}\n", update.storage_updates.len()));
            if !update.storage_updates.is_empty() {
                result.push_str("#### Storage Keys:\n");
                for (i, storage) in update.storage_updates.iter().enumerate().take(10) {
                    result.push_str(&format!("- Key: {}, Value: {}\n", storage.key, storage.value));
                    if i == 9 && update.storage_updates.len() > 10 {
                        result.push_str(&format!("- ... and {} more\n", update.storage_updates.len() - 10));
                        break;
                    }
                }
            }
            result.push_str("\n");
        }
    }
    
    // Details for contracts only in data2
    if !only_in_data2.is_empty() {
        result.push_str("## Contracts only in second file\n\n");
        for update in only_in_data2 {
            result.push_str(&format!("### Contract Address: {}\n", update.address));
            result.push_str(&format!("- Nonce: {}\n", update.nonce));
            if let Some(class_hash) = &update.new_class_hash {
                result.push_str(&format!("- Class Hash: {}\n", class_hash));
            }
            result.push_str(&format!("- Storage Updates: {}\n", update.storage_updates.len()));
            if !update.storage_updates.is_empty() {
                result.push_str("#### Storage Keys:\n");
                for (i, storage) in update.storage_updates.iter().enumerate().take(10) {
                    result.push_str(&format!("- Key: {}, Value: {}\n", storage.key, storage.value));
                    if i == 9 && update.storage_updates.len() > 10 {
                        result.push_str(&format!("- ... and {} more\n", update.storage_updates.len() - 10));
                        break;
                    }
                }
            }
            result.push_str("\n");
        }
    }
    
    // Details for contracts with differences
    if !differences.is_empty() {
        result.push_str("## Contracts with differences\n\n");
        for (address, diff) in differences {
            result.push_str(&format!("### Contract Address: {}\n", address));
            result.push_str(&diff);
            result.push_str("\n");
        }
    }
    
    // Compare class declarations
    result.push_str("\n# Comparison of Class Declarations\n\n");
    
    // Create sets for easier comparison
    let class_set1: HashSet<(BigUint, BigUint)> = data1.class_declaration
        .iter()
        .map(|decl| (decl.class_hash.clone(), decl.compiled_class_hash.clone()))
        .collect();
    
    let class_set2: HashSet<(BigUint, BigUint)> = data2.class_declaration
        .iter()
        .map(|decl| (decl.class_hash.clone(), decl.compiled_class_hash.clone()))
        .collect();
    
    // Find classes only in data1
    let only_in_data1_classes: Vec<_> = class_set1.difference(&class_set2).collect();
    
    // Find classes only in data2
    let only_in_data2_classes: Vec<_> = class_set2.difference(&class_set1).collect();
    
    // Output results
    result.push_str(&format!("Class Declaration Summary:\n"));
    result.push_str(&format!("- Total class declarations in first file: {}\n", data1.class_declaration.len()));
    result.push_str(&format!("- Total class declarations in second file: {}\n", data2.class_declaration.len()));
    result.push_str(&format!("- Class declarations only in first file: {}\n", only_in_data1_classes.len()));
    result.push_str(&format!("- Class declarations only in second file: {}\n\n", only_in_data2_classes.len()));
    
    // Details for classes only in data1
    if !only_in_data1_classes.is_empty() {
        result.push_str("## Class Declarations only in first file\n\n");
        for (class_hash, compiled_hash) in only_in_data1_classes {
            result.push_str(&format!("- Class Hash: {}, Compiled Class Hash: {}\n", class_hash, compiled_hash));
        }
        result.push_str("\n");
    }
    
    // Details for classes only in data2
    if !only_in_data2_classes.is_empty() {
        result.push_str("## Class Declarations only in second file\n\n");
        for (class_hash, compiled_hash) in only_in_data2_classes {
            result.push_str(&format!("- Class Hash: {}, Compiled Class Hash: {}\n", class_hash, compiled_hash));
        }
        result.push_str("\n");
    }
    
    result
}

/// Compares two ContractUpdate structures and outputs a detailed comparison
/// 
/// # Arguments
/// * `update1` - First ContractUpdate structure
/// * `update2` - Second ContractUpdate structure
/// 
/// # Returns
/// A string containing a detailed comparison of the two structures
fn compare_contract_updates(update1: &ContractUpdate, update2: &ContractUpdate) -> String {
    let mut result = String::new();
    let mut has_diff = false;
    
    // Compare nonces
    if update1.nonce != update2.nonce {
        result.push_str(&format!("- Nonce difference: {} vs {}\n", update1.nonce, update2.nonce));
        has_diff = true;
    }
    
    // Compare class hashes
    match (&update1.new_class_hash, &update2.new_class_hash) {
        (Some(hash1), Some(hash2)) => {
            if hash1 != hash2 {
                result.push_str(&format!("- Class Hash difference: {} vs {}\n", hash1, hash2));
                has_diff = true;
            }
        },
        (Some(hash1), None) => {
            result.push_str(&format!("- Class Hash in first file only: {}\n", hash1));
            has_diff = true;
        },
        (None, Some(hash2)) => {
            result.push_str(&format!("- Class Hash in second file only: {}\n", hash2));
            has_diff = true;
        },
        _ => {}
    }
    
    // Compare storage updates
    let mut storage_map1: HashMap<BigUint, BigUint> = HashMap::new();
    let mut storage_map2: HashMap<BigUint, BigUint> = HashMap::new();
    
    for storage in &update1.storage_updates {
        storage_map1.insert(storage.key.clone(), storage.value.clone());
    }
    
    for storage in &update2.storage_updates {
        storage_map2.insert(storage.key.clone(), storage.value.clone());
    }
    
    // Find keys in storage1 but not in storage2
    let mut only_in_storage1 = Vec::new();
    for (key, value) in &storage_map1 {
        if !storage_map2.contains_key(key) {
            only_in_storage1.push((key, value));
        }
    }
    
    // Find keys in storage2 but not in storage1
    let mut only_in_storage2 = Vec::new();
    for (key, value) in &storage_map2 {
        if !storage_map1.contains_key(key) {
            only_in_storage2.push((key, value));
        }
    }
    
    // Find keys with different values
    let mut different_values = Vec::new();
    for (key, value1) in &storage_map1 {
        if let Some(value2) = storage_map2.get(key) {
            if value1 != value2 {
                different_values.push((key, value1, value2));
            }
        }
    }
    
    if !only_in_storage1.is_empty() || !only_in_storage2.is_empty() || !different_values.is_empty() {
        has_diff = true;
        
        result.push_str(&format!("- Storage update differences:\n"));
        result.push_str(&format!("  - Storage keys only in first file: {}\n", only_in_storage1.len()));
        result.push_str(&format!("  - Storage keys only in second file: {}\n", only_in_storage2.len()));
        result.push_str(&format!("  - Storage keys with different values: {}\n", different_values.len()));
        
        // Show detailed storage differences
        if !only_in_storage1.is_empty() {
            result.push_str("  - Details of storage keys only in first file:\n");
            for (i, (key, value)) in only_in_storage1.iter().enumerate().take(5) {
                result.push_str(&format!("    - Key: {}, Value: {}\n", key, value));
                if i == 4 && only_in_storage1.len() > 5 {
                    result.push_str(&format!("    - ... and {} more\n", only_in_storage1.len() - 5));
                    break;
                }
            }
        }
        
        if !only_in_storage2.is_empty() {
            result.push_str("  - Details of storage keys only in second file:\n");
            for (i, (key, value)) in only_in_storage2.iter().enumerate().take(5) {
                result.push_str(&format!("    - Key: {}, Value: {}\n", key, value));
                if i == 4 && only_in_storage2.len() > 5 {
                    result.push_str(&format!("    - ... and {} more\n", only_in_storage2.len() - 5));
                    break;
                }
            }
        }
        
        if !different_values.is_empty() {
            result.push_str("  - Details of storage keys with different values:\n");
            for (i, (key, value1, value2)) in different_values.iter().enumerate().take(5) {
                result.push_str(&format!("    - Key: {}\n      - Value in first file: {}\n      - Value in second file: {}\n", key, value1, value2));
                if i == 4 && different_values.len() > 5 {
                    result.push_str(&format!("    - ... and {} more\n", different_values.len() - 5));
                    break;
                }
            }
        }
    }
    
    if has_diff {
        result
    } else {
        String::new()
    }
}


/// Converts a vector of BigUint values to a vector of Felt values
/// 
/// # Arguments
/// * `biguints` - Vector of BigUint values to convert
/// 
/// # Returns
/// A Result containing a vector of Felt values or an error
pub fn convert_biguints_to_felts(biguints: &[BigUint]) -> Result<Vec<Felt>> {
    biguints.iter()
        .map(|b| {
            let bytes = b.to_bytes_be();
            // Handle empty bytes case
            if bytes.is_empty() {
                return Ok(Felt::ZERO);
            }
            
            // Create a fixed size array for the bytes
            let mut field_bytes = [0u8; 32];
            
            // Copy bytes, padding with zeros if needed
            if bytes.len() <= 32 {
                let start_idx = 32 - bytes.len();
                field_bytes[start_idx..].copy_from_slice(&bytes);
            } else {
                // Truncate if bigger than 32 bytes
                field_bytes.copy_from_slice(&bytes[bytes.len() - 32..]);
            }
            
            // Convert to Felt
            Ok(Felt::from_bytes_be(&field_bytes))
    
        })
        .collect()
} 