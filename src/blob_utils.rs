use crate::constants::{BLS_MODULUS, BLOB_LEN, GENERATOR, ONE, TWO};
use num_bigint::BigUint;
use num_traits::{Num, Zero};
use rayon::prelude::*;
use std::fs::File;
use std::collections::HashSet;
use eyre::eyre;
use num_bigint::ToBigUint;
use std::fs;
use std::str;
use std::path::PathBuf;
use crate::serde_utils;
use crate::models;
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};

/// Convert field elements to BigUint representation
///
/// # Arguments
/// * `elements` - Vector of field elements (as bytes)
///
/// # Returns
/// A vector of `BigUint` values, padded to BLOB_LEN
pub fn convert_to_biguint(elements: Vec<[u8; 32]>) -> Vec<BigUint> {
    let mut biguint_vec = Vec::with_capacity(BLOB_LEN);

    // Iterate over the first BLOB_LEN elements of the input vector or until we reach BLOB_LEN elements
    for i in 0..BLOB_LEN {
        if let Some(element) = elements.get(i) {
            // Convert [u8; 32] to BigUint
            let biguint = BigUint::from_bytes_be(element);
            biguint_vec.push(biguint);
        } else {
            // If we run out of elements, push a zero BigUint
            biguint_vec.push(BigUint::zero());
        }
    }

    biguint_vec
}

/// Write a vector of BigUint values to a file
///
/// # Arguments
/// * `numbers` - Vector of BigUint values
/// * `file_path` - Path to the file
///
/// # Returns
/// Result of the file write operation
pub fn write_biguint_to_file(numbers: &Vec<BigUint>, file_path: &str) -> io::Result<()> {
    let mut file = File::create(file_path)?;
    for number in numbers {
        writeln!(file, "{}", number)?;
    }
    Ok(())
}

/// Read a vector of BigUint from a file
///
/// # Arguments
/// * `file_path` - Path to the file containing BigUint values (one per line)
///
/// # Returns
/// Result containing the vector of BigUint values or an error
pub fn read_biguint_from_file(file_path: &str) -> io::Result<Vec<BigUint>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut result = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            match BigUint::parse_bytes(trimmed.as_bytes(), 10) {
                Some(num) => result.push(num),
                None => return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse BigUint from line: {}", trimmed)
                )),
            }
        }
    }
    
    println!("Read {} BigUint values from {}", result.len(), file_path);
    Ok(result)
}

/// Perform Number Theoretic Transform (NTT) on a vector of BigUint values
///
/// # Arguments
/// * `arr` - Vector of BigUint values
/// * `xs` - Evaluation points
/// * `p` - Modulus (typically BLS_MODULUS)
///
/// # Returns
/// Transformed vector of BigUint values
pub fn ntt(arr: Vec<BigUint>, xs: Vec<BigUint>, p: &BigUint) -> Vec<BigUint> {
    // Use Rayon for parallel processing
    (0..arr.len())
        .into_par_iter()
        .map(|i| {
            let mut result = BigUint::zero();
            let mut xi_pow_j = ONE.clone(); // Initialize to xs[i]**0
            
            for j in 0..arr.len() {
                let term = (&arr[j] * &xi_pow_j) % p;
                result = (result + term) % p;
                xi_pow_j = (&xi_pow_j * &xs[i]) % p; // Update power for next iteration
            }
            
            result
        })
        .collect()
}

/// Perform Inverse Fast Fourier Transform (IFFT)
///
/// # Arguments
/// * `arr` - Vector of BigUint values
/// * `xs` - Evaluation points
/// * `p` - Modulus (typically BLS_MODULUS)
///
/// # Returns
/// Transformed vector of BigUint values
pub fn ifft(arr: Vec<BigUint>, xs: Vec<BigUint>, p: &BigUint) -> Vec<BigUint> {
    // Base case: return immediately if the array length is 1
    if arr.len() == 1 {
        return arr;
    }

    let n = arr.len() / 2;
    let mut res0 = Vec::with_capacity(n);
    let mut res1 = Vec::with_capacity(n);
    let mut new_xs = Vec::with_capacity(n);

    for i in (0..2 * n).step_by(2) {
        let a = &arr[i];
        let b = &arr[i + 1];
        let x = &xs[i];

        res0.push(div_mod(a + b, TWO.clone(), p));
        // Handle subtraction to avoid underflow
        let diff = if b > a { p - (b - a) } else { a - b };
        res1.push(div_mod(diff, TWO.clone() * x, p));

        new_xs.push(x.modpow(&TWO.clone(), p));
    }

    // Recursive calls
    let merged_res0 = ifft(res0, new_xs.clone(), p);
    let merged_res1 = ifft(res1, new_xs, p);

    // Merging the results
    let mut merged = Vec::with_capacity(arr.len());
    for i in 0..n {
        merged.push(merged_res0[i].clone());
        merged.push(merged_res1[i].clone());
    }
    merged
}

/// Helper function for modular division
///
/// # Arguments
/// * `a` - Numerator
/// * `b` - Denominator
/// * `p` - Modulus
///
/// # Returns
/// Result of (a / b) mod p
pub fn div_mod(a: BigUint, b: BigUint, p: &BigUint) -> BigUint {
    a * b.modpow(&(p - TWO.clone()), p) % p
}

/// Generate evaluation points for NTT/IFFT operations
///
/// # Arguments
/// * `size` - Size of the data (default: BLOB_LEN)
///
/// # Returns
/// A tuple of (evaluation points, modulus)
pub fn generate_evaluation_points(size: Option<usize>) -> (Vec<BigUint>, BigUint) {
    let blob_len = size.unwrap_or(BLOB_LEN);
    
    // Generate evaluation points
    let xs: Vec<BigUint> = (0..blob_len)
        .map(|i| {
            let bin = format!("{:012b}", i);
            let bin_rev = bin.chars().rev().collect::<String>();
            GENERATOR.modpow(&BigUint::from_str_radix(&bin_rev, 2).unwrap(), &BLS_MODULUS)
        })
        .collect();
    
    (xs, BLS_MODULUS.clone())
}

/// Process a vector of BigUint values for blob data transformation using NTT
///
/// # Arguments
/// * `data` - Vector of BigUint values to process
/// * `size` - Optional size parameter to override BLOB_LEN (default: BLOB_LEN)
///
/// # Returns
/// Transformed vector for blob data
pub fn process_for_blob(data: Vec<BigUint>, size: Option<usize>) -> Vec<BigUint> {
    let blob_len = size.unwrap_or(BLOB_LEN);
    
    // Get evaluation points
    let (xs, p) = generate_evaluation_points(Some(blob_len));
    
    // Ensure data is of correct length
    let mut data_padded = data;
    if data_padded.len() < blob_len {
        // Pad with zeros if needed
        data_padded.resize(blob_len, BigUint::zero());
    } else if data_padded.len() > blob_len {
        // Truncate if too long
        data_padded.truncate(blob_len);
    }
    
    // Perform NTT transformation
    let transformed_data = ntt(data_padded, xs, &p);
    
    transformed_data
}

/// Process a vector of BigUint values from blob data using IFFT
///
/// # Arguments
/// * `data` - Vector of BigUint values to process
/// * `size` - Optional size parameter to override BLOB_LEN (default: BLOB_LEN)
///
/// # Returns
/// Transformed vector from blob data
pub fn process_from_blob(data: Vec<BigUint>, size: Option<usize>) -> Vec<BigUint> {
    let blob_len = size.unwrap_or(BLOB_LEN);
    
    // Get evaluation points
    let (xs, p) = generate_evaluation_points(Some(blob_len));
    
    // Ensure data is of correct length
    let mut data_padded = data;
    if data_padded.len() < blob_len {
        // Pad with zeros if needed
        data_padded.resize(blob_len, BigUint::zero());
    } else if data_padded.len() > blob_len {
        // Truncate if too long
        data_padded.truncate(blob_len);
    }
    
    // Perform IFFT transformation
    let transformed_data = ifft(data_padded, xs, &p);
    
    transformed_data
}

/// Create a blob from BigUint data
///
/// # Arguments
/// * `data` - Vector of BigUint values
///
/// # Returns
/// Blob data as a Vec<u8>
pub fn create_blob_from_data(data: Vec<BigUint>) -> Vec<u8> {
    // Convert BigUint to bytes
    let mut blob_data = Vec::new();
    for num in data {
        let bytes = num.to_bytes_be();
        blob_data.extend_from_slice(&bytes);
    }
    blob_data
}

/// Read a file and return its content as a string
pub fn read_file_as_string(file_path: &str) -> Option<String> {
    match fs::read_to_string(file_path) {
        Ok(content) => {
            println!("Read file as text: {}", file_path);
            Some(content)
        },
        Err(e) => {
            println!("Could not read file as text: {}", e);
            None
        }
    }
}

/// Read a file and return its content as bytes
pub fn read_file_as_bytes(file_path: &str) -> Option<Vec<u8>> {
    match fs::read(file_path) {
        Ok(content) => {
            println!("Read file as binary: {} ({} bytes)", file_path, content.len());
            Some(content)
        },
        Err(e) => {
            println!("Error reading file as binary: {}", e);
            None
        }
    }
}

/// Convert a hex string to a vector of bytes
pub fn hex_string_to_u8_vec(hex_str: &str) -> Vec<u8> {
    // Remove any spaces or non-hex characters from the input string
    let cleaned_str: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    // Convert the cleaned hex string to a Vec<u8>
    let mut result = Vec::new();
    for chunk in cleaned_str.as_bytes().chunks(2) {
        if chunk.len() == 2 {
            if let Ok(s) = str::from_utf8(chunk) {
                if let Ok(byte_val) = u8::from_str_radix(s, 16) {
                    result.push(byte_val);
                } else {
                    println!("Warning: Could not parse hex digits: {:?}", chunk);
                }
            } else {
                println!("Warning: Invalid UTF-8 sequence: {:?}", chunk);
            }
        } else if chunk.len() == 1 {
            // Handle odd number of hex digits
            if let Ok(s) = str::from_utf8(&[chunk[0]]) {
                if let Ok(byte_val) = u8::from_str_radix(&format!("{}0", s), 16) {
                    result.push(byte_val >> 4);
                } else {
                    println!("Warning: Could not parse final hex digit: {:?}", chunk);
                }
            } else {
                println!("Warning: Invalid UTF-8 sequence for final digit: {:?}", chunk);
            }
        }
    }

    println!("Converted hex string to {} bytes", result.len());
    result
}

/// Convert bytes to a vector of BigUint
pub fn bytes_to_biguints(bytes: &[u8]) -> Vec<BigUint> {
    let mut result = Vec::new();
    for chunk in bytes.chunks(32) {
        let mut padded = [0u8; 32];
        let len = std::cmp::min(chunk.len(), 32);
        padded[32 - len..].copy_from_slice(&chunk[..len]);
        let num = BigUint::from_bytes_be(&padded);
        result.push(num);
    }
    
    println!("Converted {} bytes to {} BigUint values", bytes.len(), result.len());
    result
}

/// Recover BigUint values from a blob file
pub fn recover_from_blob(blob_file_path: &str) -> Vec<BigUint> {
    println!("Recovering from blob file: {}", blob_file_path);
    
    // Try to read as string first (for hex files)
    if let Some(content) = read_file_as_string(blob_file_path) {
        let bytes = hex_string_to_u8_vec(&content);
        return bytes_to_biguints(&bytes);
    }
    
    // Fall back to binary if reading as string fails
    if let Some(bytes) = read_file_as_bytes(blob_file_path) {
        return bytes_to_biguints(&bytes);
    }
    
    // Return empty vector if all methods fail
    println!("Failed to read blob file using any method");
    Vec::new()
}

/// Compress multiple blobs by removing duplicates
///
/// # Arguments
/// * `blobs` - Vector of blob data
///
/// # Returns
/// A vector of compressed blobs
pub fn compress_blobs(blobs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    // Recover all original data
    let all_data: Vec<Vec<BigUint>> = blobs.iter()
        .map(|blob| bytes_to_biguints(&blob))
        .collect();
    
    // Keep track of unique BLOB_LEN chunks and their positions
    let mut unique_chunks: HashSet<Vec<BigUint>> = HashSet::new();
    let mut positions: Vec<usize> = Vec::new();
    
    for data in all_data {
        // Process in BLOB_LEN chunks
        for chunk_start in (0..data.len()).step_by(BLOB_LEN) {
            let end = std::cmp::min(chunk_start + BLOB_LEN, data.len());
            let chunk = data[chunk_start..end].to_vec();
            
            if !unique_chunks.contains(&chunk) {
                unique_chunks.insert(chunk);
                positions.push(chunk_start);
            }
        }
    }
    
    // Create new blobs from unique chunks
    let unique_blobs = unique_chunks.into_iter()
        .map(|chunk| create_blob_from_data(chunk))
        .collect();
    
    unique_blobs
}

/// Gets all state update JSON files from a directory with their block numbers
///
/// # Arguments
/// * `directory` - Path to the directory
///
/// # Returns
/// A vector of (file path, block number) tuples, sorted by block number
pub fn get_state_update_files(directory: &str) -> color_eyre::Result<Vec<(PathBuf, u64)>> {
    let mut state_update_files = Vec::new();
    
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            let filename = path.file_name().unwrap().to_string_lossy().to_string();
            let block_number = serde_utils::extract_block_number_from_filename(&filename);
            state_update_files.push((path, block_number));
        }
    }
    
    // Sort files by block number (ascending)
    state_update_files.sort_by_key(|(_, block_num)| *block_num);
    
    Ok(state_update_files)
}
