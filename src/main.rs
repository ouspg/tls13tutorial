#![allow(dead_code)]
/// # TLS 1.3 client protocol implementation in Rust
///
/// Described data structures follow the naming convention and structure of the standard specification
/// [Standard](https://datatracker.ietf.org/doc/html/rfc8446)
/// [Visual guide](https://tls13.xargs.org/)
mod alert;
mod extensions;

use alert::Alert;
use extensions::{
    AsBytes, Extension, ExtensionType, KeyShareClientHello, KeyShareEntry, NameType, NamedGroup,
    NamedGroupList, ServerName, ServerNameList, SignatureScheme, SupportedSignatureAlgorithms,
    SupportedVersions,
};
use std::fmt::Write;
use std::io::{self, Read as SocketRead, Write as SocketWrite};
use std::net::TcpStream;

// use rand::RngCore;
use log::{debug, error, info};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

type ProtocolVersion = u16;
type Random = [u8; 32];
type CipherSuite = [u8; 2];

const TLS_VERSION_COMPATIBILITY: ProtocolVersion = 0x0303;
const TLS_VERSION_1_3: ProtocolVersion = 0x0304;

/// ## Cipher Suites
/// Our client primarily supports ChaCha20-Poly1305 with SHA-256
/// See more [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4)

const TLS_AES_128_GCM_SHA256: CipherSuite = [0x13, 0x01];
const TLS_AES_256_GCM_SHA384: CipherSuite = [0x13, 0x02];
const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = [0x13, 0x03];
const TLS_AES_128_CCM_SHA256: CipherSuite = [0x13, 0x04];
const TLS_AES_128_CCM_8_SHA256: CipherSuite = [0x13, 0x05];

/// [TLS Record Layer](https://datatracker.ietf.org/doc/html/rfc8446#section-5.1)
/// TLS Record Content Types
#[derive(Debug, Copy, Clone)]
enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[derive(Debug, Clone)]
struct TLSPlaintext {
    record_type: ContentType,
    legacy_record_version: ProtocolVersion, // 2 bytes to represent
    // always 0x0303 for TLS 1.3, except for the first ClientHello where it can be 0x0301
    length: u16,       // length defined as 2 bytes
    fragment: Vec<u8>, // fragment of size 'length'
}

impl TLSPlaintext {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.record_type as u8);
        bytes.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.fragment);
        bytes
    }
    fn from_bytes(bytes: &[u8]) -> io::Result<TLSPlaintext> {
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
        let legacy_record_version = u16::from_be_bytes(bytes[1..3].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid TLSPlaintext version")
        })?);
        let length = u16::from_be_bytes([bytes[3], bytes[4]]);
        let fragment = bytes[5..].to_vec();
        Ok(TLSPlaintext {
            record_type,
            legacy_record_version,
            length,
            fragment,
        })
    }
}

#[derive(Debug, Copy, Clone)]
enum HandshakeType {
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
enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello,
    EndOfEarlyData,
    EncryptedExtensions,
    CertificateRequest,
    Certificate,
    CertificateVerify,
    Finished,
    NewSessionTicket,
    KeyUpdate,
}

#[derive(Debug, Clone)]
struct Handshake {
    msg_type: HandshakeType,
    length: u32, // length of the data can be 0..2^24-1 (3 bytes to present)
    message: HandshakeMessage,
}

impl AsBytes for Handshake {
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
            _ => {}
        }
        Some(bytes)
    }
}

/// [`ClientHello`](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2)
/// TLS 1.3 `ClientHello`s are identified as having
///       a `legacy_version` of 0x0303 and a `supported_versions` extension
///       present with 0x0304 as the highest version indicated therein.
///       (See Appendix D for details about backward compatibility.)
#[derive(Clone)]
struct ClientHello {
    legacy_version: ProtocolVersion,
    random: Random,                      // Static 32 bytes, no length prefix
    legacy_session_id: Vec<u8>,          // length of the data can be 0..32 (1 byte to present)
    cipher_suites: Vec<CipherSuite>,     // length of the data can be 2..2^16-2 (2 bytes)
    legacy_compression_methods: Vec<u8>, // length of the data can be 1..2^8-1 (1 byte)
    extensions: Vec<Extension>,          // length of the data can be 8..2^16-1 (2 bytes to present)
}

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
        let len_ciphers: usize = self.cipher_suites.iter().fold(0, |acc, x| acc + x.len());
        #[allow(clippy::cast_possible_truncation)]
        bytes.extend_from_slice((len_ciphers as u16).to_be_bytes().as_ref());
        for cipher_suite in &self.cipher_suites {
            bytes.extend_from_slice(cipher_suite);
        }
        bytes
    }
    fn compression_methods_bytes(&self) -> Vec<u8> {
        vec![0x01, 0x00] // TLS 1.3 does not support compression
    }
    fn extensions_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for extension in &self.extensions {
            bytes.extend(extension.as_bytes()?);
        }
        // 2 byte length determinant for `extensions`
        bytes.splice(
            0..0,
            u16::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );
        Some(bytes)
    }
}
impl AsBytes for ClientHello {
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
}
/// Debug method prints data also in tag-length-value format
/// To use it, just call object as `dbg!(&client_hello)`, for example
impl std::fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHello")
            .field("legacy_version", &self.version_bytes())
            .field("random", &self.random_bytes())
            .field("legacy_session_id", &self.session_id_bytes())
            .field("cipher_suites", &self.cipher_suites_bytes())
            .field(
                "legacy_compression_methods",
                &self.compression_methods_bytes(),
            )
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// `ServerHello` message
#[derive(Debug, Clone)]
struct ServerHello {
    legacy_version: ProtocolVersion,
    random: Random,
    legacy_session_id_echo: Vec<u8>,
    // length of the data can be 0..32
    cipher_suite: CipherSuite,
    legacy_compression_method: u8,
    extensions: Vec<Extension>, // length of the data can be 6..2^16-1 (2 bytes to present)
}

fn parse_tls_record_layer(stream: &mut TcpStream) -> io::Result<TLSPlaintext> {
    // Max size for single block is 2^14 https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
    let mut buffer = [0; 2 ^ 14];
    let mut bytes = Vec::new();
    match stream.read(&mut buffer) {
        Ok(n) => {
            debug!("Received {n} bytes of data.");
            bytes.extend_from_slice(&buffer[..n]);
            debug!("Data: {bytes:?}");
            TLSPlaintext::from_bytes(&bytes)
        }
        // Rust handles buffer overflows with runtime checks
        Err(e) => Err(e),
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    // Creating logger.
    // You can change the level with RUST_LOG environment variable, e.g. RUST_LOG=debug
    env_logger::init();

    // X25519 key generation
    let alice_secret = EphemeralSecret::random_from_rng(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let public_key_hex: String =
        alice_public
            .to_bytes()
            .iter()
            .fold(String::new(), |mut output, byte| {
                let _ = write!(output, "{byte:02x}");
                output
            });
    debug!("Public key in hex string format: {public_key_hex}");

    let address = "cloudflare.com:443";

    // Generate 32 bytes of random data
    // let seed_random = rand::random::<[u8; 32]>();
    // FIXME use random data instead of hardcoded seed
    // Hardcoded value has been used for debugging purposes
    let seed_random = [
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    // let random_session_id = rand::random::<[u8; 32]>();
    let random_session_id = seed_random;

    match TcpStream::connect(address) {
        Ok(mut stream) => {
            info!("Successfully connected to the server '{address}'.");

            let client_hello = ClientHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: seed_random,
                legacy_session_id: random_session_id.to_vec(),
                cipher_suites: vec![TLS_CHACHA20_POLY1305_SHA256],
                legacy_compression_methods: vec![0],
                extensions: vec![
                    Extension {
                        extension_type: ExtensionType::SupportedVersions,
                        extension_data: SupportedVersions {
                            versions: vec![TLS_VERSION_1_3],
                        }
                        .as_bytes()
                        .expect("Failed to serialize SupportedVersions"),
                    },
                    Extension {
                        extension_type: ExtensionType::ServerName,
                        extension_data: ServerNameList {
                            server_name_list: vec![ServerName {
                                name_type: NameType::HostName,
                                name: "cloudflare.com".as_bytes().to_vec(),
                            }],
                        }
                        .as_bytes()
                        .expect("Failed to serialize ServerNameList"),
                    },
                    Extension {
                        extension_type: ExtensionType::SupportedGroups,
                        extension_data: NamedGroupList {
                            named_group_list: vec![NamedGroup::X25519],
                        }
                        .as_bytes()
                        .expect("Failed to serialize NamedGroupList"),
                    },
                    Extension {
                        extension_type: ExtensionType::SignatureAlgorithms,
                        extension_data: SupportedSignatureAlgorithms {
                            supported_signature_algorithms: vec![SignatureScheme::Ed25519],
                        }
                        .as_bytes()
                        .expect("Failed to serialize SupportedSignatureAlgorithms"), // Ed25519
                    },
                    Extension {
                        extension_type: ExtensionType::KeyShare,
                        extension_data: KeyShareClientHello {
                            client_shares: vec![KeyShareEntry {
                                group: NamedGroup::X25519,
                                key_exchange: alice_public.to_bytes().to_vec(),
                            }],
                        }
                        .as_bytes()
                        .expect("Failed to serialize KeyShareClientHello"),
                    },
                ],
            };
            debug!("Sending ClientHello: {:?}", client_hello);
            // dbg!(&client_hello);
            let handshake = Handshake {
                msg_type: HandshakeType::ClientHello,
                length: u32::try_from(
                    client_hello
                        .as_bytes()
                        .expect("Failed to serialize ClientHello message into bytes")
                        .len(),
                )
                .expect("ClientHello message too long"),
                message: HandshakeMessage::ClientHello(client_hello),
            };
            let handshake_bytes = handshake
                .as_bytes()
                .expect("Failed to serialize Handshake message into bytes");
            let request = TLSPlaintext {
                record_type: ContentType::Handshake,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: u16::try_from(handshake_bytes.len()).expect("Handshake message too long"),
                fragment: handshake_bytes,
            };
            // println!("ClientHello: {:?}", request.as_bytes());

            // Send the constructed request to the server
            match stream.write_all(&request.as_bytes()) {
                Ok(()) => {
                    info!("The handshake request has been sent...");
                }
                Err(e) => {
                    info!("Failed to send the request: {e}");
                }
            }
            // Read the response data into a buffer
            match parse_tls_record_layer(&mut stream) {
                Ok(response) => {
                    info!("Response received: {response:?}");
                    match response.record_type {
                        ContentType::Alert => match Alert::from_bytes(&response.fragment) {
                            Ok(alert) => {
                                println!("Alert received: {alert}");
                            }
                            Err(e) => {
                                println!("Failed to parse the alert: {e}");
                            }
                        },
                        _ => {
                            error!("Unexpected response type: {:?}", response.record_type);
                        }
                    }
                }
                Err(e) => {
                    println!("Failed to receive the response: {e}");
                }
            }
            // Additional code to read the response would go here.
        }
        Err(e) => {
            println!("Failed to connect: {e}");
        }
    }
}