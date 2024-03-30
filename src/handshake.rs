//! This module contains the structures and implementations for the handshake messages.
#![allow(clippy::module_name_repetitions)]
use crate::extensions::{ByteSerializable, Extension, ExtensionOrigin};
use crate::handshake::cipher_suites::CipherSuite;
use crate::parser::ByteParser;
use std::collections::VecDeque;

pub type ProtocolVersion = u16;
pub type Random = [u8; 32];

pub const TLS_VERSION_COMPATIBILITY: ProtocolVersion = 0x0303;
pub const TLS_VERSION_1_3: ProtocolVersion = 0x0304;

/// ## Cipher Suites
/// TLS 1.3 supports only five different cipher suites
/// Our client primarily supports ChaCha20-Poly1305 with SHA-256
/// See more [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4)
pub mod cipher_suites {
    #[derive(Debug, Copy, Clone)]
    pub struct CipherSuite([u8; 2]);
    impl CipherSuite {
        pub fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl From<[u8; 2]> for CipherSuite {
        fn from(slice: [u8; 2]) -> Self {
            CipherSuite(slice)
        }
    }
    impl From<Vec<u8>> for CipherSuite {
        fn from(slice: Vec<u8>) -> Self {
            let mut arr = [0u8; 2];
            arr.copy_from_slice(&slice);
            CipherSuite(arr)
        }
    }
    pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite([0x13, 0x01]);
    pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite([0x13, 0x02]);
    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite([0x13, 0x03]);
    pub const TLS_AES_128_CCM_SHA256: CipherSuite = CipherSuite([0x13, 0x04]);
    pub const TLS_AES_128_CCM_8_SHA256: CipherSuite = CipherSuite([0x13, 0x05]);
    /// Pretty print the cipher suite
    impl std::fmt::Display for CipherSuite {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                [0x13, 0x01] => write!(f, "[0x13, 0x01] TLS_AES_128_GCM_SHA256"),
                [0x13, 0x02] => write!(f, "[0x13, 0x02] TLS_AES_256_GCM_SHA384"),
                [0x13, 0x03] => write!(f, "[0x13, 0x03] TLS_CHACHA20_POLY1305_SHA256"),
                [0x13, 0x04] => write!(f, "[0x13, 0x04] TLS_AES_128_CCM_SHA256"),
                [0x13, 0x05] => write!(f, "[0x13, 0x05] TLS_AES_128_CCM_8_SHA256"),
                e => write!(f, "Unknown Cipher Suite: {e:?}"),
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

#[derive(Debug, Clone)]
pub enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EndOfEarlyData,
    EncryptedExtensions,
    CertificateRequest,
    Certificate(Certificate),
    CertificateVerify,
    Finished(Finished),
    NewSessionTicket,
    KeyUpdate,
}

#[derive(Debug, Clone)]
pub struct Handshake {
    pub msg_type: HandshakeType,
    pub length: u32, // length of the data can be 0..2^24-1 (3 bytes to present)
    pub message: HandshakeMessage,
}

impl ByteSerializable for Handshake {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.push(self.msg_type as u8);
        if self.length <= 0x00FF_FFFF {
            // convert u32 to 3 bytes
            bytes.extend_from_slice(&self.length.to_be_bytes()[1..]);
        } else {
            return None;
        }
        match &self.message {
            HandshakeMessage::ClientHello(client_hello) => {
                bytes.extend_from_slice(&client_hello.as_bytes()?);
            }
            HandshakeMessage::Finished(finished) => {
                bytes.extend_from_slice(&finished.as_bytes()?);
            }
            _ => {}
        }
        Some(bytes)
    }

    /// Parse the bytes into a `Handshake` struct.
    /// We only support `ServerHello`, `Certificate`, `CertificateVerify` and `Finished` messages.
    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        let hs_type = match bytes.get_u8() {
            Some(1) => HandshakeType::ClientHello,
            Some(2) => HandshakeType::ServerHello,
            Some(11) => HandshakeType::Certificate,
            Some(15) => HandshakeType::CertificateVerify,
            Some(20) => HandshakeType::Finished,
            e => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid or unimplemented handshake type: {e:?}"),
                ))
            }
        };
        let msg_length = bytes.get_u24().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid handshake message length",
            )
        })?;
        let hs_message = match hs_type {
            HandshakeType::ClientHello => {
                let client_hello = ClientHello::from_bytes(bytes)?;
                HandshakeMessage::ClientHello(*client_hello)
            }
            HandshakeType::ServerHello => {
                let server_hello = ServerHello::from_bytes(bytes)?;
                HandshakeMessage::ServerHello(*server_hello)
            }
            HandshakeType::Certificate => {
                let certificate = Certificate::from_bytes(bytes)?;
                HandshakeMessage::Certificate(*certificate)
            }
            HandshakeType::Finished => {
                let finished = Finished::from_bytes(bytes)?;
                HandshakeMessage::Finished(*finished)
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid handshake message type",
                ))
            }
        };
        Ok(Box::from(Handshake {
            msg_type: hs_type,
            length: msg_length,
            message: hs_message,
        }))
    }
}

/// `Finished` message is the final message in the Authentication Block.
#[derive(Debug, Clone)]
pub struct Finished {
    pub verify_data: Vec<u8>, // length can be presented with single byte
}
impl ByteSerializable for Finished {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        todo!("Implement Finished::as_bytes")
    }
    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement Finished::from_bytes")
    }
}

/// [`ClientHello`](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2)
/// TLS 1.3 `ClientHello`s are identified as having
///       a `legacy_version` of 0x0303 and a `supported_versions` extension
///       present with 0x0304 as the highest version indicated therein.
///       (See Appendix D for details about backward compatibility.)
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub legacy_version: ProtocolVersion,     // 2 bytes to represent
    pub random: Random,                      // Static 32 bytes, no length prefix
    pub legacy_session_id: Vec<u8>,          // length of the data can be 0..32 (1 byte to present)
    pub cipher_suites: Vec<CipherSuite>,     // length of the data can be 2..2^16-2 (2 bytes)
    pub legacy_compression_methods: Vec<u8>, // length of the data can be 1..2^8-1 (1 byte)
    pub extensions: Vec<Extension>, // length of the data can be 8..2^16-1 (2 bytes to present)
}

/// Implements inner encoders and decoders for `ClientHello` struct.
/// For clarity, each field is encoded separately to bytes.
impl ClientHello {
    fn version_bytes(&self) -> Vec<u8> {
        self.legacy_version.to_be_bytes().to_vec()
    }
    fn random_bytes(&self) -> &[u8] {
        self.random.as_ref()
    }
    fn session_id_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        bytes.push(self.legacy_session_id.len() as u8);
        bytes.extend_from_slice(self.legacy_session_id.as_slice());
        bytes
    }
    fn cipher_suites_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let len_ciphers: usize = self.cipher_suites.iter().fold(0, |acc, _x| acc + 2);
        #[allow(clippy::cast_possible_truncation)]
        bytes.extend_from_slice((len_ciphers as u16).to_be_bytes().as_ref());
        for cipher_suite in &self.cipher_suites {
            bytes.extend_from_slice(cipher_suite.as_ref());
        }
        bytes
    }

    #[allow(clippy::unused_self)]
    fn compression_methods_bytes(&self) -> Vec<u8> {
        vec![0x01, 0x00] // TLS 1.3 does not support compression
    }
    fn extensions_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut ext_bytes = Vec::new();
        for extension in &self.extensions {
            ext_bytes.extend(extension.as_bytes()?);
        }
        // 2 byte length determinant for `extensions`
        bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
        bytes.extend(ext_bytes);
        Some(bytes)
    }
}

impl ByteSerializable for ClientHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(&self.version_bytes());
        bytes.extend_from_slice(self.random_bytes());
        bytes.extend(&self.session_id_bytes());
        bytes.extend(&self.cipher_suites_bytes());
        bytes.extend(&self.compression_methods_bytes());
        bytes.extend(&self.extensions_bytes()?);
        Some(bytes)
    }

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement ClientHello::from_bytes")
    }
}

/// `ServerHello` message
#[derive(Debug, Clone)]
pub struct ServerHello {
    pub legacy_version: ProtocolVersion,
    pub random: Random,
    pub legacy_session_id_echo: Vec<u8>, // length of the data can be 0..32
    pub cipher_suite: CipherSuite,
    pub legacy_compression_method: u8,
    pub extensions: Vec<Extension>, // length of the data can be 6..2^16-1 (2 bytes to present)
}
impl ByteSerializable for ServerHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(self.legacy_version.to_be_bytes().iter());
        bytes.extend(self.random.iter());
        bytes.push(u8::try_from(self.legacy_session_id_echo.len()).ok()?);
        bytes.extend(self.legacy_session_id_echo.iter());
        bytes.extend(self.cipher_suite.as_ref());
        bytes.push(self.legacy_compression_method);
        let mut ext_bytes = Vec::new();
        for extension in &self.extensions {
            ext_bytes.extend(extension.as_bytes()?);
        }
        bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
        bytes.extend(ext_bytes);
        Some(bytes)
    }
    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        let checksum;
        #[cfg(debug_assertions)]
        {
            checksum = bytes.deque.clone();
        }

        let legacy_version = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello legacy version",
            )
        })?;
        let random: Random = bytes.get_bytes(32).try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello random",
            )
        })?;
        let session_id_length = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello session id length",
            )
        })?;
        let session_id = bytes.get_bytes(session_id_length as usize);
        let cipher_suite: CipherSuite = bytes.get_bytes(2).into();
        let compression_method = bytes.get_u8().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello compression method",
            )
        })?;
        let extension_length = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid ServerHello extension length",
            )
        })?;
        let mut extensions = Vec::new();
        let extension_bytes = bytes.get_bytes(extension_length as usize);
        let mut ext_parser = ByteParser::new(VecDeque::from(extension_bytes));

        while !ext_parser.deque.is_empty() {
            let extension = Extension::from_bytes(&mut ext_parser, ExtensionOrigin::Server)?;
            extensions.push(*extension);
        }

        let server_hello = Box::from(ServerHello {
            legacy_version,
            random,
            legacy_session_id_echo: session_id,
            cipher_suite,
            legacy_compression_method: compression_method,
            extensions,
        });
        // Helper to identify that decoded bytes are encoded back to the same bytes
        #[cfg(debug_assertions)]
        {
            assert_eq!(checksum, server_hello.as_bytes().unwrap());
        }
        Ok(server_hello)
    }
}

/// `CertificateType` which is presented with 1-byte enum values
#[derive(Debug, Copy, Clone)]
pub enum CertificateType {
    X509 = 0,
    RawPublicKey = 2,
}
/// A single certificate and set of extensions as defined in Section 4.2.
#[derive(Debug, Clone)]
pub struct CertificateEntry {
    pub certificate_type: CertificateType,
    pub certificate_data: Vec<u8>, // length of the data can be 1..2^24-1 (3 bytes to present)
    pub extensions: Vec<Extension>,
}
/// [`Certificate` message](https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2)
///  This message conveys the endpoint's certificate chain to the peer.
#[derive(Debug, Clone)]
pub struct Certificate {
    pub certificate_request_context: Vec<u8>, // length of the data can be 0..255 (1 byte to present)
    pub certificate_list: Vec<CertificateEntry>, // length of the data can be 0..2^24-1 (3 bytes to present)
}

impl ByteSerializable for Certificate {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        todo!("Implement Certificate::as_bytes")
    }
    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement Certificate::from_bytes")
    }
}
