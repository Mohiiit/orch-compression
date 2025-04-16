use std::fs;

use crate::models::{ClassDeclaration, ContractUpdate, DataJson, StorageUpdate, CompressedStateUpdate, StateDiff};
use crate::compression;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use serde_json;
use color_eyre::eyre::Result;
use serde::Serialize;
use starknet::core::types::{StateUpdate, Felt};

const BLOB_LEN: usize = 4096;

/// Function to parse the encoded data into a DataJson struct.
/// # Arguments
/// * `data` - A slice of `BigUint` representing the encoded data.
/// # Returns
/// A `DataJson` struct containing the parsed data.
pub fn parse_state_diffs(data: &[BigUint]) -> DataJson {
    if data.is_empty() {
        println!("Error: Empty data array");
        return DataJson {
            state_update_size: 0,
            state_update: Vec::new(),
            class_declaration_size: 0,
            class_declaration: Vec::new(),
        };
    }

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
    
    // iterate only on len-1 because (len-1)th element contains the length
    // of declared classes
    for _ in 0..contract_updated_num {
        if i >= data.len() {
            println!("Warning: Reached end of data while reading contract updates");
            break;
        }
        
        let address = data[i].clone();
        // Break if address undefined
        if address == BigUint::zero() {
            break;
        }
        i += 1;
        
        // Break after blob data len or end of data
        if i >= data.len() || i >= BLOB_LEN - 1 {
            println!("Warning: Reached end of data or blob length limit");
            break;
        }
        
        let info_word = &data[i];
        let (class_flag, nonce, number_of_storage_updates) = extract_bits(&info_word);
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
            // Break if we reached the end of data or blob length limit
            if i + 1 >= data.len() || i >= BLOB_LEN - 1 {
                println!("Warning: Reached end of data or blob length limit while reading storage updates");
                break;
            }
            
            let key = data[i].clone();
            i += 1;
            let value = data[i].clone();
            i += 1;
            
            // Skip null entries
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

    // Check if we have enough data to read the declared classes length
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
        // Break if address undefined
        if class_hash == BigUint::zero() {
            println!("Warning: Found zero class hash when expecting non-zero");
            break;
        }
        i += 1;
        
        // Break if we reached the end of data or blob length limit
        if i >= data.len() || i >= BLOB_LEN - 1 {
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

    let final_result = DataJson {
        state_update_size: (contract_updated_num - 1).to_u64().unwrap_or(0),
        state_update: updates,
        class_declaration_size: declared_classes_len.to_u64().unwrap_or(0),
        class_declaration: class_declaration_updates,
    };

    final_result
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
///
/// # Returns
/// A Vec<BigUint> suitable for blob creation
pub async fn json_to_blob_data(json_str: &str, block_no: u64) -> Result<Vec<BigUint>> {
    // Parse the JSON into a StateUpdate
    let state_update: StateUpdate = serde_json::from_str(json_str)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to parse JSON as StateUpdate: {}", e))?;
    
    // Convert StateUpdate to Felt vector
    let felts = compression::state_update_to_blob_data(block_no, state_update).await?;

    println!("felts size is: {:?}", felts.len());
    
    // Convert Felt vector to BigUint vector
    let biguints = convert_to_biguint(felts);
    
    Ok(biguints)
}

pub fn convert_to_biguint(elements: Vec<Felt>) -> Vec<BigUint> {
    // Initialize the vector with 4096 BigUint zeros
    let mut biguint_vec = vec![BigUint::zero(); 4096];

    // Iterate over the elements and replace the zeros in the biguint_vec
    for (i, element) in elements.iter().take(4096).enumerate() {
        // Convert FieldElement to [u8; 32]
        let bytes: [u8; 32] = element.to_bytes_be();

        // Convert [u8; 32] to BigUint
        let biguint = BigUint::from_bytes_be(&bytes);

        // Replace the zero with the converted value
        biguint_vec[i] = biguint;
    }

    biguint_vec
}