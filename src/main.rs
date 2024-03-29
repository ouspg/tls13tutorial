#![allow(dead_code)]
/// # TLS 1.3 client protocol implementation in Rust
///
/// Described data structures follow the naming convention and structure of the standard specification
/// [Standard](https://datatracker.ietf.org/doc/html/rfc8446)
/// [Visual guide](https://tls13.xargs.org/)
mod alert;
mod extensions;
mod handshake;
mod macros;
mod parser;
mod tls_record;

use alert::Alert;
use extensions::{
    ByteSerializable, Extension, ExtensionType, KeyShareClientHello, KeyShareEntry, NameType,
    NamedGroup, NamedGroupList, ServerName, ServerNameList, SignatureScheme,
    SupportedSignatureAlgorithms, SupportedVersions,
};
use handshake::{
    cipher_suites, ClientHello, Handshake, HandshakeMessage, HandshakeType, Random,
    TLS_VERSION_1_3, TLS_VERSION_COMPATIBILITY,
};
use log::{debug, error, info, warn};
use parser::ByteParser;
use rand::rngs::OsRng;
use std::collections::VecDeque;
use std::io::{self, Read as SocketRead, Write as SocketWrite};
use std::net::TcpStream;
use tls_record::{ContentType, TLSRecord};

// Cryptographic libraries
use hkdf::Hkdf;
// use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
///        if log::max_level() == log::LevelFilter::Debug {
//             let public_key_hex: String =
//                 dh_client_public
//                     .to_bytes()
//                     .iter()
//                     .fold(String::new(), |mut output, byte| {
//                         let _ = write!(output, "{byte:02x}");
//                         output
//                     });
//             debug!("Public key in hex string format: {public_key_hex}");
//         }

// #[derive(Debug)]
/// Key calculation and resulting keys, includes initial random values for `ClientHello`
/// Check section about [KeySchedule](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
struct HandshakeKeys {
    random_seed: Random,
    session_id: Random,
    dh_client_ephemeral_secret: EphemeralSecret,
    dh_client_public: PublicKey,
    dh_server_public: PublicKey,
    dh_shared_secret: Vec<u8>,
    client_hs_key: Vec<u8>,
    client_hs_iv: Vec<u8>,
    client_hs_finished_key: Vec<u8>,
    client_seq_num: u64,
    server_hs_key: Vec<u8>,
    server_hs_iv: Vec<u8>,
    server_hs_finished_key: Vec<u8>,
    server_seq_num: u64,
}
impl HandshakeKeys {
    fn new() -> Self {
        // Key length is 32 bytes in SHA-256

        // Generate 32 bytes of random data
        // let seed_random = rand::random::<[u8; 32]>();
        // FIXME use random data instead of hardcoded seed
        // Hardcoded value has been used for debugging purposes
        let random_seed = [
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f,
        ];
        // let random_session_id = rand::random::<[u8; 32]>();
        let session_id = random_seed;
        // Generate a new Elliptic Curve Diffie-Hellman public-private key pair (X25519)
        let dh_client_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let dh_client_public = PublicKey::from(&dh_client_ephemeral_secret);

        Self {
            random_seed,
            session_id,
            dh_client_ephemeral_secret,
            dh_client_public,
            dh_server_public: PublicKey::from([0u8; 32]),
            dh_shared_secret: vec![0u8; 32],
            client_hs_key: vec![0u8; 16],
            client_hs_iv: vec![0u8; 12],
            client_hs_finished_key: vec![0u8; 32],
            client_seq_num: 0,
            server_hs_key: vec![0u8; 16],
            server_hs_iv: vec![0u8; 12],
            server_hs_finished_key: vec![0u8; 32],
            server_seq_num: 0,
        }
    }
    /// Update the keys based on handshake messages
    /// See especially Section 7. in the standard
    fn key_schedule(&mut self, shared_secret: &SharedSecret, transcript_hash: &[u8]) {
        // Early secret - we don't implement PSK, need to use empty arrays
        let (early_secret, _hk) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &[0u8; 32]);
        let pre_secret = Self::derive_secret(&early_secret, b"derived", &[], 32);

        // Handshake secrets with Key & IV pairs
        let (handshake_secret, _hk) =
            Hkdf::<Sha256>::extract(Some(&pre_secret), shared_secret.as_ref());
        let client_hs_traffic_secret =
            Self::derive_secret(&handshake_secret, b"c hs traffic", transcript_hash, 32);
        self.client_hs_key = Self::derive_secret(&client_hs_traffic_secret, b"key", &[], 16);
        self.client_hs_iv = Self::derive_secret(&client_hs_traffic_secret, b"iv", &[], 12);
        self.client_hs_finished_key =
            Self::derive_secret(&client_hs_traffic_secret, b"finished", &[], 32);
        let server_hs_traffic_secret =
            Self::derive_secret(&handshake_secret, b"s hs traffic", transcript_hash, 32);
        self.server_hs_key = Self::derive_secret(&server_hs_traffic_secret, b"key", &[], 16);
        self.server_hs_iv = Self::derive_secret(&server_hs_traffic_secret, b"iv", &[], 12);
        self.server_hs_finished_key =
            Self::derive_secret(&server_hs_traffic_secret, b"finished", &[], 32);
    }
    /// Expand the secret with the label and transcript hash (hash bytes of the combination of messages)
    fn derive_secret(
        secret: &[u8],
        label: &[u8],
        transcript_hash: &[u8],
        length: usize,
    ) -> Vec<u8> {
        let mut hkdf_label = Vec::new();
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        // All the labels are ASCII strings, prepend with "tls13 "
        hkdf_label.extend_from_slice(b"tls13 ");
        hkdf_label.extend_from_slice(label);
        hkdf_label.extend_from_slice(transcript_hash);
        let hk = Hkdf::<Sha256>::from_prk(secret).expect("Failed to create HKDF from PRK");
        let mut okm = vec![0u8; length];
        hk.expand(&hkdf_label, &mut okm)
            .expect("Failed to expand the secret");
        okm
    }
}

/// Process the data from TCP stream in the chunks of 4096 bytes and
/// read the response data into a buffer in a form of Queue for easier parsing.
fn process_tcp_stream(mut stream: &mut TcpStream) -> io::Result<VecDeque<u8>> {
    let mut reader = io::BufReader::new(&mut stream);
    let mut buffer: VecDeque<u8> = VecDeque::new();

    loop {
        let mut chunk = [0; 4096];
        match reader.read(&mut chunk) {
            Ok(0) => break, // Connection closed by the sender
            Ok(n) => {
                debug!("Received {n} bytes of data.");
                buffer.extend(&chunk[..n]);
            }
            Err(e) => {
                error!("Error when reading from the TCP stream: {}", e);
                return Err(e);
            }
        }
    }
    Ok(buffer)
}

fn handle_handshake_message(bytes: &mut ByteParser) {
    let handshake = Handshake::from_bytes(bytes).expect("Failed to parse Handshake message");
    match handshake.message {
        HandshakeMessage::ServerHello(server_hello) => {
            info!("ServerHello message received: {server_hello:?}");
            // Get the server public key
            let extensions = server_hello.extensions;
            for extension in extensions {
                match extension.extension_type {
                    ExtensionType::KeyShare => {
                        debug!(
                            "KeyShare extension found, extension data: {:?}",
                            extension.extension_data
                        );
                        // let key_share =
                        //     KeyShareClientHello::from_bytes(&mut extension.extension_data.into())
                        //         .expect("Failed to parse KeyShareClientHello");
                        // let key_share_entry = key_share
                        //     .client_shares
                        //     .first()
                        //     .expect("No key shares found");
                        // let dh_server_public = key_share_entry.key_exchange.clone();
                        // debug!("Server public key: {dh_server_public:?}");
                    }
                    _ => {
                        debug!("Extension type: {:?}", extension.extension_type);
                    }
                }
            }
        }
        _ => {
            error!("Unexpected handshake message: {:?}", handshake.message);
        }
    }
}
#[allow(clippy::too_many_lines)]
fn main() {
    // Get address as command-line argument, e.g. cargo run cloudflare.com:443
    let args = std::env::args().collect::<Vec<String>>();
    let address = if args.len() > 1 {
        args[1].as_str()
    } else {
        eprintln!("Usage: {} <address:port>", args[0]);
        std::process::exit(1);
    };
    // Creating logger.
    // You can change the level with RUST_LOG environment variable, e.g. RUST_LOG=debug
    env_logger::init();

    // Note: unsafe, not  everything-covering validation for the address
    let Some((hostname, _port)) = address.split_once(':') else {
        error!("Invalid address:port format");
        std::process::exit(1);
    };
    let handshake_keys = HandshakeKeys::new();

    match TcpStream::connect(address) {
        Ok(mut stream) => {
            info!("Successfully connected to the server '{address}'.");

            // Generate the ClientHello message with the help of the data structures
            let client_hello = ClientHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: handshake_keys.random_seed.into(),
                legacy_session_id: handshake_keys.session_id.into(),
                cipher_suites: vec![cipher_suites::TLS_CHACHA20_POLY1305_SHA256],
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
                                name: hostname.to_string().as_bytes().to_vec(),
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
                                key_exchange: handshake_keys.dh_client_public.to_bytes().to_vec(),
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

            let request_record = TLSRecord {
                record_type: ContentType::Handshake,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: u16::try_from(handshake_bytes.len()).expect("Handshake message too long"),
                fragment: handshake_bytes,
            };
            // Send the constructed request to the server
            match stream.write_all(
                &request_record
                    .as_bytes()
                    .expect("Failed to serialize TLSPlaintext"),
            ) {
                Ok(()) => {
                    info!("The handshake request has been sent...");
                }
                Err(e) => {
                    error!("Failed to send the request: {e}");
                }
            }
            // Read all the response data into a `VecDeque` buffer
            let buffer = process_tcp_stream(&mut stream).unwrap_or_else(|e| {
                error!("Failed to read the response: {e}");
                std::process::exit(1)
            });
            let mut parser = ByteParser::new(buffer);

            // Assume we get multiple TLS Records in a single response

            // In this case, first one should be `ServerHello` message if the `ClientHello`
            // was correct and offered supported cipher suites
            while !parser.deque.is_empty() {
                match TLSRecord::from_bytes(&mut parser) {
                    Ok(response) => {
                        info!("Response TLS Record received!");
                        debug!("Response bytes: {:?}", response);
                        match response.record_type {
                            ContentType::Alert => {
                                match Alert::from_bytes(&mut response.fragment.into()) {
                                    Ok(alert) => {
                                        warn!("Alert received: {alert}");
                                    }
                                    Err(e) => {
                                        error!("Failed to parse the alert: {e}");
                                    }
                                }
                            }
                            ContentType::Handshake => {
                                debug!("Raw handshake data: {:?}", response.fragment);
                                handle_handshake_message(&mut response.fragment.into());
                            }
                            _ => {
                                error!("Unexpected response type: {:?}", response.record_type);
                                // debug!("Remaining bytes: {:?}", parser.deque);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to receive the response: {e}");
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to connect: {e}");
        }
    }
}
