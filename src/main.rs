#![allow(dead_code)]
/// # TLS 1.3 client protocol implementation in Rust
///
/// Described data structures follow the naming convention and structure of the standard specification
/// [Standard](https://datatracker.ietf.org/doc/html/rfc8446)
/// [Visual guide](https://tls13.xargs.org/)
mod alert;
mod extensions;
mod handshake;
mod tls_record;

use alert::Alert;
use extensions::{
    AsBytes, Extension, ExtensionType, KeyShareClientHello, KeyShareEntry, NameType, NamedGroup,
    NamedGroupList, ServerName, ServerNameList, SignatureScheme, SupportedSignatureAlgorithms,
    SupportedVersions,
};
use handshake::{
    cipher_suites, ClientHello, Handshake, HandshakeMessage, HandshakeType, TLS_VERSION_1_3,
    TLS_VERSION_COMPATIBILITY,
};
use log::{debug, error, info, warn};
use rand::rngs::OsRng;
use std::fmt::Write;
use std::io::{self, Read as SocketRead, Write as SocketWrite};
use std::net::TcpStream;
use tls_record::{ContentType, TLSPlaintext, TLSRecord};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Generate a new Elliptic Curve Diffie-Hellman public-private key pair
fn generate_dh_key_pair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    if log::max_level() == log::LevelFilter::Debug {
        let public_key_hex: String =
            public
                .to_bytes()
                .iter()
                .fold(String::new(), |mut output, byte| {
                    let _ = write!(output, "{byte:02x}");
                    output
                });
        debug!("Public key in hex string format: {public_key_hex}");
    }
    (secret, public)
}
/// Process the data from TCP stream in the chunks of 4096 bytes and
/// read the response data into a buffer.
fn process_tcp_stream(mut stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut reader = io::BufReader::new(&mut stream);
    let mut buffer = Vec::new();

    loop {
        let mut chunk = [0; 4096];
        match reader.read(&mut chunk) {
            Ok(0) => break, // Connection closed by the sender
            Ok(n) => {
                debug!("Received {n} bytes of data.");
                buffer.extend_from_slice(&chunk[..n]);
            }
            Err(e) => {
                error!("Error when reading from the TCP stream: {}", e);
                return Err(e);
            }
        }
    }
    Ok(buffer)
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

    // Note: unsafe, not  everything-covering validation for the address
    let Some((hostname, _port)) = address.split_once(':') else {
        error!("Invalid address:port format");
        std::process::exit(1);
    };
    // Creating logger.
    // You can change the level with RUST_LOG environment variable, e.g. RUST_LOG=debug
    env_logger::init();
    // X25519 key generation
    let (_alice_secret, alice_public) = generate_dh_key_pair();

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

            // Generate the ClientHello message with the help of the data structures
            let client_hello = ClientHello {
                legacy_version: TLS_VERSION_COMPATIBILITY,
                random: seed_random,
                legacy_session_id: random_session_id.to_vec(),
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
            let request_record = TLSPlaintext {
                record_type: ContentType::Handshake,
                legacy_record_version: TLS_VERSION_COMPATIBILITY,
                length: u16::try_from(handshake_bytes.len()).expect("Handshake message too long"),
                fragment: handshake_bytes,
            };
            // Send the constructed request to the server
            match stream.write_all(&request_record.as_bytes()) {
                Ok(()) => {
                    info!("The handshake request has been sent...");
                }
                Err(e) => {
                    error!("Failed to send the request: {e}");
                }
            }
            // Read all the response data into a buffer
            let buffer = process_tcp_stream(&mut stream).unwrap_or_else(|e| {
                error!("Failed to read the response: {e}");
                std::process::exit(1)
            });

            // Read the initial response data into a buffer
            // In this case, it should be `ServerHello` message if the `ClientHello`
            // was correct and offered supported cipher suites
            match TLSPlaintext::from_bytes(&buffer) {
                Ok((response, remainder_bytes)) => {
                    info!("Response received: {response:?}");
                    match response.record_type {
                        ContentType::Alert => match Alert::from_bytes(&response.fragment) {
                            Ok(alert) => {
                                warn!("Alert received: {alert}");
                            }
                            Err(e) => {
                                error!("Failed to parse the alert: {e}");
                            }
                        },
                        ContentType::Handshake => {
                            info!("Handshake message received: {:?}", response.fragment);
                            todo!("Handle the ServerHello handshake response")
                        }
                        _ => {
                            error!("Unexpected response type: {:?}", response.record_type);
                            debug!("Remaining bytes: {:?}", remainder_bytes);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to receive the response: {e}");
                }
            }
        }
        Err(e) => {
            error!("Failed to connect: {e}");
        }
    }
}
