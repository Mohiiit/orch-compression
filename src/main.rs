mod blob_utils;
mod compression;
mod constants;
mod models;
mod serde_utils;

use color_eyre::eyre::Result;
use dotenv::dotenv;
use std::env;
use std::fs;
use std::path::Path;
use std::process;
use starknet::{
    core::types::{BlockId, BlockTag},
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        Provider, Url,
    }, 
};

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
        process::exit(1);
    }
    
    match args[1].as_str() {
        "compress" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression compress <input_dir> <output_file>");
                eprintln!("  input_dir - Directory containing state update JSON files named <name>_<block_number>.json");
                eprintln!("  output_file - File to write compressed state updates to");
                process::exit(1);
            }
            
            let input_dir = &args[2];
            let output_file = &args[3];
            
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
        
        "blob" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression blob <input_file> <output_file>");
                process::exit(1);
            }
            
            let input_file = &args[2];
            let output_file = &args[3];
            
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
        
        "recover" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression recover <blob_file> <output_file>");
                process::exit(1);
            }
            
            let blob_file = &args[2];
            let output_file = &args[3];
            
            // Extract file name from the blob file path
            let file_name = Path::new(output_file)
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
            let post_process_file = format!("post_process_blob_{}.txt", file_name);
            println!("Writing processed blob data to {}", post_process_file);
            blob_utils::write_biguint_to_file(&processed_data, &post_process_file)?;
            
            // Parse state diffs from processed data
            println!("Parsing state diffs from processed data");
            let state_diffs = serde_utils::parse_state_diffs(&processed_data);
            
            // Save parsed state diffs to squashed_state_diff_from_blob_<file_name>.json
            let state_diff_file = format!("squashed_state_diff_from_blob_{}.json", file_name);
            println!("Writing parsed state diffs to {}", state_diff_file);
            let json_str = serde_utils::to_json(state_diffs);
            fs::write(&state_diff_file, json_str)?;
            
            println!("Recovery completed successfully");
        },
        
        "multi-blob" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression multi-blob <input_dir> <output_dir>");
                process::exit(1);
            }
            
            let input_dir = &args[2];
            let output_dir = &args[3];
            
            // Ensure output directory exists
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
                    let data_json = serde_utils::parse_state_diffs(&blob_data);
                    
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
        
        "fetch-update" => {
            if args.len() < 3 {
                eprintln!("Usage: orch-compression fetch-update <output_dir> [start_block] [end_block]");
                process::exit(1);
            }
            
            let output_dir = &args[2];
            
            // Ensure output directory exists
            fs::create_dir_all(output_dir)?;
            
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
                            
                            // Create filename
                            let output_path = Path::new(output_dir).join(format!("state_update_{}.json", block_num));
                            
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
                        
                        // Create filename
                        let output_path = Path::new(output_dir).join("state_update_latest.json");
                        
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
        
        "merge-json" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression merge-json <input_dir> <output_file>");
                eprintln!("  input_dir - Directory containing state update JSON files named <n>_<block_number>.json");
                eprintln!("  output_file - File to write merged JSON to");
                process::exit(1);
            }
            
            let input_dir = &args[2];
            let output_file = &args[3];
            
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
            let json_str = match compression::merge_state_update_files_to_json(state_update_files) {
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
        
        "json-to-blob" => {
            if args.len() < 4 {
                eprintln!("Usage: orch-compression json-to-blob <input_file> <output_file> [block_number]");
                process::exit(1);
            }
            
            let input_file = &args[2];
            let output_file = &args[3];
            
            // Get optional block number
            let block_number = if args.len() >= 5 {
                args[4].parse::<u64>().unwrap_or(0)
            } else {
                0 // Default block number if not provided
            };
            
            println!("Reading JSON from {}", input_file);
            let json_str = fs::read_to_string(input_file)?;
            
            println!("Converting JSON to blob");
            let blob_data = serde_utils::json_to_blob_data(&json_str, block_number).await?;
            
            println!("Writing blob to {}", output_file);
            blob_utils::write_biguint_to_file(&blob_data, output_file)?;
            
            println!("JSON to blob conversion completed successfully");
        },
        
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
            process::exit(1);
        }
    }
    
    Ok(())
}
