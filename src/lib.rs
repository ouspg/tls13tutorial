//! # TLS 1.3 client protocol implementation in Rust
//!
//! Described data structures follow the naming convention and structure of the standard specification
//!
//! [Standard](https://datatracker.ietf.org/doc/html/rfc8446)
//!
//! [Visual guide](https://tls13.xargs.org/)
pub mod alert;
pub mod display;
pub mod extensions;
pub mod handshake;
pub mod macros;
pub mod parser;
pub mod tls_record;
use crate::extensions::ByteSerializable;
use crate::parser::ByteParser;
use crate::tls_record::TLSRecord;
use log::{error, info};
use std::collections::VecDeque;
use std::io;

/// Get all TLS Records from the byte buffer.
/// Assume we get multiple TLS Records in a single response.
/// # Errors
/// Returns an error if the data is not completely parsed as TLS records
pub fn get_records(buffer: VecDeque<u8>) -> Result<Vec<TLSRecord>, io::Error> {
    let mut records = Vec::new();
    let mut parser = ByteParser::new(buffer);
    while !parser.deque.is_empty() {
        match TLSRecord::from_bytes(&mut parser) {
            Ok(response) => {
                info!("Response TLS Record received!");
                records.push(*response);
            }
            Err(e) => {
                error!("Failed to receive a valid TLS Record: {e}");
                return Err(e);
            }
        }
    }
    Ok(records)
}
