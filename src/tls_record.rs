use crate::handshake::ProtocolVersion;
use log::debug;
use std::collections::VecDeque;
use std::io;

const RECORD_FRAGMENT_MAX_SIZE: u16 = 2u16.pow(14);

/// [TLS Record Layer](https://datatracker.ietf.org/doc/html/rfc8446#section-5.1)
/// TLS Record Content Types
///
pub trait ByteSerializable {
    fn as_bytes(&self) -> Vec<u8>;
    // Attempts to parse the bytes into a `TLSRecord` struct, returning remaining bytes
    fn from_bytes(bytes: &mut VecDeque<u8>) -> io::Result<Box<Self>>;

    // fn parse_payload(_bytes: &[u8]) -> io::Result<Box<Self>>;
}

#[derive(Debug, Copy, Clone)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[derive(Debug, Clone)]
pub struct TLSPlaintext {
    pub record_type: ContentType,
    pub legacy_record_version: ProtocolVersion, // 2 bytes to represent
    // always 0x0303 for TLS 1.3, except for the first ClientHello where it can be 0x0301
    pub length: u16,       // length defined as 2 bytes
    pub fragment: Vec<u8>, // fragment of size 'length'
}

impl ByteSerializable for TLSPlaintext {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.record_type as u8);
        bytes.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.fragment);
        bytes
    }
    /// Parse the bytes into a `TLSPlaintext` struct
    /// Returns `Result` object with the parsed `TLSPlaintext` object and the remaining bytes
    /// `Box` structure is used to wrap the data of the struct into a heap-allocated memory
    /// In stack, only the pointer to the heap memory is stored to make compiler known the size
    /// of the return type in compile-time.
    /// NOTE The implementation might not be secure...
    fn from_bytes(bytes: &mut VecDeque<u8>) -> io::Result<Box<TLSPlaintext>> {
        if bytes.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TLSPlaintext length too short: {}", bytes.len()),
            ));
        }
        let record_type = match bytes.pop_front().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Insufficient bytes for TLSPlaintext record type",
            )
        })? {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        };
        // FIXME Using plain indexes in general for parsing is not recommended!
        let legacy_record_version = u16::from_be_bytes(
            bytes
                .drain(..2)
                .collect::<Vec<u8>>()
                .try_into()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid TLSPlaintext version")
                })?,
        );

        // Max size for single block is 2^14 https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
        // The length MUST NOT exceed 2^14 bytes.
        //  An endpoint that receives a record that exceeds this length MUST
        //  terminate the connection with a "record_overflow" alert.
        let length = u16::from_be_bytes(bytes.drain(..2).collect::<Vec<u8>>().try_into().map_err(
            |_| io::Error::new(io::ErrorKind::InvalidData, "Invalid TLSPlaintext length"),
        )?);
        debug!("TLSPlaintext defined length: {}", length);
        if length > RECORD_FRAGMENT_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid TLSPlaintext: record overflow",
            ));
        }
        if bytes.len() > length as usize {
            let fragment = bytes.drain(..length as usize).collect();
            Ok(Box::from(TLSPlaintext {
                record_type,
                legacy_record_version,
                length,
                fragment,
            }))
        } else {
            if bytes.len() != length as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLSPlaintext: length and fragment size mismatch",
                ));
            }
            Ok(Box::from(TLSPlaintext {
                record_type,
                legacy_record_version,
                length,
                fragment: bytes.drain(..).collect(),
            }))
        }
    }
}
