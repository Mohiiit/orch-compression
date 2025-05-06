// This file contains the main entry point for the orch-compression utility.
// It handles command-line arguments and dispatches to the appropriate functionality
// based on the command provided by the user.
mod blob_utils;
mod compression;
mod constants;
mod models;
mod serde_utils;
mod stateless_compression;

use color_eyre::eyre::Result;
use dotenv::dotenv;
use std::env;
use std::fs;
use std::path::Path;
use std::process;
use starknet::{
    core::types::{BlockId, BlockTag, Felt},
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        Provider, Url,
    }, 
};

/// Main function for the orch-compression utility
/// 
/// This function:
/// 1. Initializes error handling
/// 2. Loads environment variables
/// 3. Parses command line arguments
/// 4. Dispatches to the appropriate command handler
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize error handling
    color_eyre::install()?;
    
    // Load environment variables from .env file if it exists
    dotenv().ok();
    
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: orch-compression <command> [arguments]");
        eprintln!("Commands:");
        eprintln!("  compress <input_dir> <output_file> - Compress state updates from input directory and write to output file");
        eprintln!("  blob <input_file> <output_file> - Create a blob from input file and write to output file");
        eprintln!("  recover <blob_file> <output_file> - Recover original data from a blob file");
        eprintln!("  multi-blob <input_dir> <output_dir> - Process multiple state updates and create optimized blobs");
        eprintln!("  fetch-update <output_dir> [start_block] [end_block] - Fetch state updates from Starknet and save to output directory");
        eprintln!("  merge-json <input_dir> <output_file> - Merge state updates from input directory and write pure JSON to output file");
        eprintln!("  json-to-blob <input_file> <output_file> - Convert a JSON state update file directly to a blob");
        eprintln!("  blob-to-dataJson <input_file> <output_file> - Convert a BigUint file to DataJson format");
        eprintln!("  compare-json <file1> <file2> <output_file> - Compare two DataJson files and output differences");
        eprintln!("  stateless-decompression <input_file> <output_file> - Decompress a BigUint file using stateless decompression");
        eprintln!("  stateful-compression <input_file> <output_file> - Compress a merged state update using stateful compression");
        process::exit(1);
    }
    
    // Dispatch to the appropriate command handler based on the first argument
    match args[1].as_str() {
        // Command: compress
        // Compresses state updates from an input directory and writes to an output file
        "compress" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression compress <input_dir> <output_file>");
                eprintln!("  input_dir - Directory containing state update JSON files named <name>_<block_number>.json");
                eprintln!("  output_file - File to write compressed state updates to");
                process::exit(1);
            }
            
            let input_dir = &args[2];
            let output_file_name = &args[3];
            
            // Create output directory
            let output_dir = "output/compress";
            fs::create_dir_all(output_dir)?;
            let output_file = format!("{}/{}", output_dir, output_file_name);
            
            println!("Processing state updates from directory: {}", input_dir);
            
            // Get all JSON files from directory, sorted by block number
            let state_update_files = match blob_utils::get_state_update_files(input_dir) {
                Ok(files) => files,
                Err(e) => {
                    eprintln!("Error reading directory {}: {}", input_dir, e);
                    process::exit(1);
                }
            };
            
            if state_update_files.is_empty() {
                eprintln!("Error: No JSON files found in {}", input_dir);
                process::exit(1);
            }
            
            println!("Found {} state update files, processing in block order", state_update_files.len());
            
            // Merge state updates from all files
            let merged_data = match compression::merge_state_update_files(state_update_files) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error merging state updates: {}", e);
                    process::exit(1);
                }
            };
            
            println!("Converting to JSON");
            let json_str = serde_utils::to_json(merged_data);
            
            println!("Writing compressed data to {}", output_file);
            fs::write(output_file, json_str)?;
            
            println!("Compression completed successfully");
        },
        
        // Command: blob
        // Creates a blob from an input file and writes to an output file
        "blob" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression blob <input_file> <output_file>");
                process::exit(1);
            }
            
            let input_file = &args[2];
            let output_file_name = &args[3];
            
            // Create output directory
            let output_dir = "output/blob";
            fs::create_dir_all(output_dir)?;
            let output_file = format!("{}/{}", output_dir, output_file_name);
            
            println!("Reading data from {}", input_file);
            let blob_data = serde_utils::parse_file_to_blob_data(input_file)?;
            
            println!("Processing data for blob");
            let processed_data = blob_utils::process_for_blob(blob_data, None);
            
            println!("Creating blob");
            let blob = blob_utils::create_blob_from_data(processed_data);
            
            println!("Writing blob to {}", output_file);
            fs::write(output_file, blob)?;
            
            println!("Blob creation completed successfully");
        },
        
        // Command: recover
        // Recovers original data from a blob file and saves to specified outputs
        "recover" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression recover <blob_file> <output_file>");
                process::exit(1);
            }
            
            let blob_file = &args[2];
            let output_file_name = &args[3];
            
            // Create output directory
            let output_dir = "output/recover";
            fs::create_dir_all(output_dir)?;
            
            // Extract file name from the blob file path
            let file_name = Path::new(output_file_name)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
            
            println!("Reading blob from {}", blob_file);
            let blob_data_string = blob_utils::read_file_as_string(blob_file)
                .expect("Failed to read blob file");
            let blob_data = blob_utils::hex_string_to_u8_vec(&blob_data_string);
            
            println!("Recovering data from blob");
            let recovered_data = blob_utils::bytes_to_biguints(&blob_data);
            
            // Get the size of the recovered data (or use default BLOB_LEN)
            let size = if recovered_data.len() > 0 { Some(recovered_data.len()) } else { None };
            
            println!("Processing recovered data (size: {})", size.unwrap_or(constants::BLOB_LEN));
            let processed_data = blob_utils::process_from_blob(recovered_data, size);
            
            // Save processed data to post_process_blob_<file_name>.txt
            let post_process_file = format!("{}/post_process_blob_{}.txt", output_dir, file_name);
            println!("Writing processed blob data to {}", post_process_file);
            blob_utils::write_biguint_to_file(&processed_data, &post_process_file)?;
            
            println!("Recovery completed successfully");
        },
        
        // Command: multi-blob
        // Processes multiple state updates and creates optimized blobs
        "multi-blob" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression multi-blob <input_dir> <output_dir>");
                process::exit(1);
            }
            
            let input_dir = &args[2];
            
            // Create output directory
            let output_dir = "output/multi-blob";
            fs::create_dir_all(output_dir)?;
            
            println!("Processing state updates from {}", input_dir);
            
            // Collect all state update files
            let entries = fs::read_dir(input_dir)?;
            let mut all_blobs = Vec::new();
            
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    println!("Processing file: {:?}", path);
                    
                    // Read and parse the file
                    let blob_data = serde_utils::parse_file_to_blob_data(path.to_str().unwrap())?;
                    
                    // Parse state diffs
                    let data_json = serde_utils::parse_state_diffs(&blob_data, "0.13.3");
                    
                    // Compress state updates
                    let _compressed_data = compression::compress_state_updates(data_json);
                    
                    // Process for blob
                    let processed_data = blob_utils::process_for_blob(blob_data, None);
                    
                    // Create blob
                    let blob = blob_utils::create_blob_from_data(processed_data);
                    all_blobs.push(blob);
                }
            }
            
            println!("Compressing blobs");
            let compressed_blobs = blob_utils::compress_blobs(all_blobs);
            
            println!("Writing compressed blobs to {}", output_dir);
            for (i, blob) in compressed_blobs.iter().enumerate() {
                let output_path = Path::new(output_dir).join(format!("blob_{}.dat", i));
                fs::write(&output_path, blob)?;
                println!("Wrote blob to {:?}", output_path);
            }
            
            println!("Multi-blob processing completed successfully");
        },
        
        // Command: fetch-update
        // Fetches state updates from Starknet and saves to an output directory
        "fetch-update" => {
            if args.len() < 3 {
                eprintln!("Usage: orch-compression fetch-update <output_dir> [start_block] [end_block]");
                process::exit(1);
            }
            
            let user_dir = &args[2];
            
            // Create base output directory and user-specified subdirectory
            let base_output_dir = "output/fetch-update";
            let full_output_dir = format!("{}/{}", base_output_dir, user_dir);
            fs::create_dir_all(&full_output_dir)?;
            
            // Get RPC URL from .env file or use default
            let rpc_url = env::var("STARKNET_RPC_URL")
                .unwrap_or_else(|_| "https://free-rpc.nethermind.io/sepolia-juno/".to_string());
            
            println!("Using RPC URL: {}", rpc_url);
            
            // Create Starknet provider
            let provider = JsonRpcClient::new(HttpTransport::new(
                Url::parse(&rpc_url).map_err(|e| color_eyre::eyre::eyre!("Invalid URL: {}", e))?,
            ));
            
            // Determine if we're fetching a range or just the latest block
            let start_block = if args.len() >= 4 {
                match args[3].parse::<u64>() {
                    Ok(num) => num,
                    Err(_) => {
                        eprintln!("Error: start_block must be a number");
                        process::exit(1);
                    }
                }
            } else {
                println!("Warning: No start block specified, fetching only the latest state update");
                0
            };
            
            let end_block = if args.len() >= 5 {
                match args[4].parse::<u64>() {
                    Ok(num) => num,
                    Err(_) => {
                        eprintln!("Error: end_block must be a number");
                        process::exit(1);
                    }
                }
            } else if args.len() >= 4 {
                // If only start_block is specified, use it as both start and end
                start_block
            } else {
                0
            };
            
            if args.len() >= 4 {
                println!("Fetching state updates from block {} to {}", start_block, end_block);
                
                if end_block < start_block {
                    eprintln!("Error: end_block must be greater than or equal to start_block");
                    process::exit(1);
                }
                
                for block_num in start_block..=end_block {
                    println!("Fetching state update for block {}", block_num);
                    
                    let result = provider
                        .get_state_update(BlockId::Number(block_num))
                        .await;
                    
                    match result {
                        Ok(state_update) => {
                            println!("State update for block {} fetched successfully", block_num);
                            
                            // Convert to JSON
                            let json_str = serde_json::to_string_pretty(&state_update)
                                .map_err(|e| color_eyre::eyre::eyre!("Failed to serialize state update: {}", e))?;
                            
                            // Create filename using full_output_dir instead of output_dir
                            let output_path = Path::new(&full_output_dir)
                                .join(format!("state_update_{}.json", block_num));
                            
                            // Write to file
                            println!("Writing state update to {:?}", output_path);
                            fs::write(output_path, json_str)?;
                        },
                        Err(err) => {
                            eprintln!("Error fetching state update for block {}: {}", block_num, err);
                            // Continue with the next block rather than stopping
                        }
                    }
                }
                
                println!("Fetch operations completed");
            } else {
                println!("Fetching latest state update from Starknet...");
                
                // Fetch latest state update
                let result = provider
                    .get_state_update(BlockId::Tag(BlockTag::Latest))
                    .await;
                
                match result {
                    Ok(state_update) => {
                        println!("State update fetched successfully");
                        
                        // Convert to JSON
                        let json_str = serde_json::to_string_pretty(&state_update)
                            .map_err(|e| color_eyre::eyre::eyre!("Failed to serialize state update: {}", e))?;
                        
                        // Create filename using full_output_dir instead of output_dir
                        let output_path = Path::new(&full_output_dir)
                            .join("state_update_latest.json");
                        
                        // Write to file
                        println!("Writing state update to {:?}", output_path);
                        fs::write(output_path, json_str)?;
                        
                        println!("State update fetched and saved successfully");
                    },
                    Err(err) => {
                        return Err(color_eyre::eyre::eyre!("Failed to fetch state update: {}", err));
                    }
                }
            }
        },
        
        // Command: merge-json
        // Merges state updates from an input directory and writes to a JSON output file
        "merge-json" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression merge-json <input_dir> <output_file>");
                eprintln!("  input_dir - Directory containing state update JSON files named <n>_<block_number>.json");
                eprintln!("  output_file - File to write merged JSON to");
                eprintln!("  version - Version of the state update file (optional, default: 0.13.3)");
                process::exit(1);
            }
            
            let input_dir = &args[2];
            let output_file_name = &args[3];
            let version = &args[4];
            // Create output directory
            let output_dir = "output/merge-json";
            fs::create_dir_all(output_dir)?;
            let output_file = format!("{}/{}", output_dir, output_file_name);
            
            println!("Processing state updates from directory: {}", input_dir);
            
            // Get all JSON files from directory, sorted by block number
            let state_update_files = match blob_utils::get_state_update_files(input_dir) {
                Ok(files) => files,
                Err(e) => {
                    eprintln!("Error reading directory {}: {}", input_dir, e);
                    process::exit(1);
                }
            };
            
            if state_update_files.is_empty() {
                eprintln!("Error: No JSON files found in {}", input_dir);
                process::exit(1);
            }
            
            println!("Found {} state update files, processing in block order", state_update_files.len());
            
            // Merge state updates from all files to JSON
            let json_str = match compression::merge_state_update_files_to_json(state_update_files, version).await {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("Error merging state updates: {}", e);
                    process::exit(1);
                }
            };
            
            println!("Writing merged JSON to {}", output_file);
            fs::write(output_file, json_str)?;
            
            println!("JSON merge completed successfully");
        },
        
        // Command: json-to-blob
        // Converts a JSON state update file directly to a blob
        "json-to-blob" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression json-to-blob <input_file> <output_file> [block_number] [version]");
                process::exit(1);
            }
            
            let input_file = &args[2];
            let output_file_name = &args[3];
            let version = &args[4];
            
            // Create output directory
            let output_dir = "output/json-to-blob";
            fs::create_dir_all(output_dir)?;
            let output_file = format!("{}/{}", output_dir, output_file_name);
            
            // Get optional block number
            let block_number = if args.len() >= 5 {
                args[4].parse::<u64>().unwrap_or(0)
            } else {
                0 // Default block number if not provided
            };
            
            println!("Reading JSON from {}", input_file);
            let json_str = fs::read_to_string(input_file)?;
            
            println!("Converting JSON to blob");
            let blob_data = serde_utils::json_to_blob_data(&json_str, block_number, version).await?;
            
            println!("Writing blob to {}", output_file);
            blob_utils::write_biguint_to_file(&blob_data, &output_file)?;
            
            println!("JSON to blob conversion completed successfully");
        },
        
        // Command: blob-to-dataJson
        // Converts a BigUint file to DataJson format
        "blob-to-dataJson" => {
            if args.len() < 5 {
                eprintln!("Usage: orch-compression blob-to-dataJson <input_file> <output_file>");
                eprintln!("  input_file - BigUint file to convert");
                eprintln!("  output_file - File to write DataJson to");
                eprintln!("  version - Version of the state update file (optional, default: 0.13.3)");
                process::exit(1);
            }
            
            let input_file = &args[2];
            let output_file_name = &args[3];
            let version = &args[4];
            
            // Create output directory
            let output_dir = "output/blob-to-dataJson";
            fs::create_dir_all(output_dir)?;
            let output_file = format!("{}/{}", output_dir, output_file_name);
            
            println!("Reading BigUint data from {}", input_file);
            let blob_data = blob_utils::read_biguint_from_file(input_file)?;
            
            println!("Parsing state diffs from BigUint data");
            let data_json = serde_utils::parse_state_diffs(&blob_data, version);
            
            println!("Converting to JSON");
            let json_str = serde_utils::to_json(data_json);
            
            println!("Writing DataJson to {}", output_file);
            fs::write(output_file, json_str)?;
            
            println!("BigUint to DataJson conversion completed successfully");
        },
        
        // Command: compare-json
        // Compares two DataJson files and outputs the differences
        "compare-json" => {
            if args.len() < 5 {
                return Err(color_eyre::eyre::eyre!("Usage: orch-compression compare-json <file1> <file2> <output_file>"));
            }

            let file1 = &args[2];
            let file2 = &args[3];
            let output_file = &args[4];

            // Create output directory if it doesn't exist
            let output_dir = "output/compare-json";
            fs::create_dir_all(output_dir)?;
            let output_path = format!("{}/{}", output_dir, output_file);

            println!("Reading first JSON file: {}", file1);
            let json1 = fs::read_to_string(file1)?;
            let data_json1 = serde_utils::parse_json_to_data_json(&json1)?;

            println!("Reading second JSON file: {}", file2);
            let json2 = fs::read_to_string(file2)?;
            let data_json2 = serde_utils::parse_json_to_data_json(&json2)?;

            println!("Comparing JSON files...");
            let comparison = serde_utils::compare_data_json(data_json1, data_json2);

            println!("Writing comparison report to: {}", output_path);
            fs::write(&output_path, comparison)?;
            
            println!("Comparison complete. Report written to {}", output_path);
        },
        
        // Command: stateless-decompression
        // Decompresses a file containing BigUint data using stateless decompression
        "stateless-decompression" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression stateless-decompression <input_file> <output_file>");
                eprintln!("  input_file - File containing BigUint data to decompress");
                eprintln!("  output_file - File to write decompressed BigUint data to");
                process::exit(1);
            }
            
            let input_file = &args[2];
            let output_file_name = &args[3];
            
            // Create output directory
            let output_dir = "output/stateless-decompression";
            fs::create_dir_all(output_dir)?;
            let output_file = format!("{}/{}", output_dir, output_file_name);
            
            println!("Reading BigUint data from {}", input_file);
            let biguint_data = blob_utils::read_biguint_from_file(input_file)?;
            
            println!("Converting BigUint data to Felt array");
            let felt_data = match serde_utils::convert_biguints_to_felts(&biguint_data) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error converting BigUint to Felt: {}", e);
                    process::exit(1);
                }
            };
            
            println!("Performing stateless decompression");
            let decompressed_felts = match stateless_compression::decompress(&felt_data) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error during decompression: {}", e);
                    process::exit(1);
                }
            };
            
            println!("Converting decompressed Felt data back to BigUint");
            let decompressed_biguints = serde_utils::convert_to_biguint(&decompressed_felts);
            
            println!("Writing decompressed data to {}", output_file);
            blob_utils::write_biguint_to_file(&decompressed_biguints, &output_file)?;
            
            println!("Stateless decompression completed successfully");
        },
        
        // Command: stateful-compression
        "stateful-compression" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression stateful-compression <input_file> <output_file>");
                eprintln!("  input_file - JSON file containing merged state updates");
                eprintln!("  output_file - File to write compressed state update to");
                process::exit(1);
            }
            
            let input_file = &args[2];
            let output_file_name = &args[3];
            
            // Create output directory
            let output_dir = "output/stateful-compression";
            fs::create_dir_all(output_dir)?;
            let output_file = format!("{}/{}", output_dir, output_file_name);
            
            println!("Reading merged state update from {}", input_file);
            let file_content = fs::read_to_string(input_file)?;
            
            // Parse and compress
            let compressed_update = compression::stateful_compress_state_update(&file_content)?;
            
            // Convert to JSON and write
            let json_str = serde_json::to_string_pretty(&compressed_update)
                .map_err(|e| color_eyre::eyre::eyre!("Failed to serialize compressed state update: {}", e))?;
            
            println!("Writing compressed state update to {}", output_file);
            fs::write(output_file, json_str)?;
            
            println!("Stateful compression completed successfully");
        },
        
        // Unknown command handler
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Usage: orch-compression <command> [arguments]");
            eprintln!("Commands:");
            eprintln!("  compress <input_dir> <output_file> - Compress state updates from input directory and write to output file");
            eprintln!("  blob <input_file> <output_file> - Create a blob from input file and write to output file");
            eprintln!("  recover <blob_file> <output_file> - Recover original data from a blob file");
            eprintln!("  multi-blob <input_dir> <output_dir> - Process multiple state updates and create optimized blobs");
            eprintln!("  fetch-update <output_dir> [start_block] [end_block] - Fetch state updates from Starknet and save to output directory");
            eprintln!("  merge-json <input_dir> <output_file> - Merge state updates from input directory and write pure JSON to output file");
            eprintln!("  json-to-blob <input_file> <output_file> - Convert a JSON state update file directly to a blob");
            eprintln!("  blob-to-dataJson <input_file> <output_file> - Convert a BigUint file to DataJson format");
            eprintln!("  compare-json <file1> <file2> <output_file> - Compare two DataJson files and output differences");
            eprintln!("  stateless-decompression <input_file> <output_file> - Decompress a BigUint file using stateless decompression");
            eprintln!("  stateful-compression <input_file> <output_file> - Compress a merged state update using stateful compression");
            process::exit(1);
        }
    }
    
    Ok(())
}
