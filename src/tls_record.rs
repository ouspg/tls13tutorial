use crate::ProtocolVersion;
use std::io;

/// [TLS Record Layer](https://datatracker.ietf.org/doc/html/rfc8446#section-5.1)
/// TLS Record Content Types

pub trait TLSRecord {
    fn as_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> io::Result<Box<Self>>;

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

impl TLSRecord for TLSPlaintext {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.record_type as u8);
        bytes.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.fragment);
        bytes
    }
    /// Parse the bytes into a `TLSPlaintext` struct
    /// Returns `Result` object with the parsed `TLSPlaintext` object
    /// `Box` structure is used to wrap the data of the struct into a heap-allocated memory
    /// In stack, only the pointer to the heap memory is stored to make compiler known the size
    /// of the return type in compile-time.
    fn from_bytes(bytes: &[u8]) -> io::Result<Box<TLSPlaintext>> {
        if bytes.len() < 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid TLSPlaintext length",
            ));
        }
        let record_type = match bytes[0] {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Invalid,
        };
        // FIXME Using plain indexes in general for parsing is not recommended!
        let legacy_record_version = u16::from_be_bytes(bytes[1..3].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid TLSPlaintext version")
        })?);
        let length = u16::from_be_bytes([bytes[3], bytes[4]]);
        let fragment = bytes[5..].to_vec();
        Ok(Box::from(TLSPlaintext {
            record_type,
            legacy_record_version,
            length,
            fragment,
        }))
    }
}
