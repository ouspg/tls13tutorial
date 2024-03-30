//! # TLS Extensions and their encoding/decoding
//!
//! Includes `ByteSerializable` trait for converting structures into bytes and constructing again.
use crate::handshake::ProtocolVersion;
use crate::parser::ByteParser;
use ::log::{debug, warn};

/// `ByteSerializable` trait is used to serialize and deserialize the struct into bytes
pub trait ByteSerializable {
    /// Returns the byte representation of the object if possible
    fn as_bytes(&self) -> Option<Vec<u8>>;
    /// Attempts to parse the bytes into a struct object implementing this trait
    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>>;
}

/// Helper to identify the origin of the extension (client or server)
/// Extension data format is different for client and server on some cases
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ExtensionOrigin {
    Client,
    Server,
}

/// `Extension` is wrapper for any TLS extension
#[derive(Debug, Clone)]
pub struct Extension {
    pub origin: ExtensionOrigin,
    pub extension_type: ExtensionType, // Defined maximum value can be 65535, takes 2 bytes to present
    pub extension_data: ExtensionData, // length of the data can be 0..2^16-1 (2 bytes to present)
}

impl Extension {
    pub(crate) fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice((self.extension_type as u16).to_be_bytes().as_ref());
        let ext_bytes = self.extension_data.as_bytes()?;
        // 2 byte length determinant for the `extension_data`
        bytes.extend(u16::try_from(ext_bytes.len()).ok()?.to_be_bytes());
        bytes.extend_from_slice(&ext_bytes);
        Some(bytes)
    }

    pub(crate) fn from_bytes(
        bytes: &mut ByteParser,
        origin: ExtensionOrigin,
    ) -> std::io::Result<Box<Self>> {
        let ext_type = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid extension type")
        })?;
        debug!("ExtensionType: {:?}", ext_type);

        let ext_data_len = bytes.get_u16().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid extension data length",
            )
        })?;
        debug!("Extension data length: {}", ext_data_len);
        let ext_data = bytes.get_bytes(ext_data_len as usize);
        let mut ext_bytes = ByteParser::from(ext_data);
        debug!("Extension data: {:?}", ext_bytes);
        // let extension_data = match ext_type {
        // TODO Implement the rest of the extension types
        //     0 => ExtensionData::ServerName(*ServerNameList::from_bytes(&mut ext_bytes)?),
        //     _ => {
        //         warn!("Unknown ExtensionType: {}", ext_type);
        //         return Err(std::io::Error::new(
        //             std::io::ErrorKind::InvalidData,
        //             "Invalid extension data",
        //         ));
        //     }
        // };
        // Use placeholder `Unserialized` for now, not all extension data types are implemented
        Ok(Box::new(Extension {
            origin,
            extension_type: ext_type.into(),
            extension_data: ExtensionData::Unserialized(ext_bytes.drain()),
        }))
    }
}

/// `ExtensionType` where maximum value can be 2^16-1 (2 bytes to present)
#[derive(Debug, Copy, Clone)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
}
/// By using `From` trait, we can convert `u16` to `ExtensionType`, e.g. by using `.into()`
impl From<u16> for ExtensionType {
    fn from(value: u16) -> Self {
        match value {
            0 => ExtensionType::ServerName,
            1 => ExtensionType::MaxFragmentLength,
            5 => ExtensionType::StatusRequest,
            10 => ExtensionType::SupportedGroups,
            13 => ExtensionType::SignatureAlgorithms,
            14 => ExtensionType::UseSrtp,
            15 => ExtensionType::Heartbeat,
            16 => ExtensionType::ApplicationLayerProtocolNegotiation,
            18 => ExtensionType::SignedCertificateTimestamp,
            19 => ExtensionType::ClientCertificateType,
            20 => ExtensionType::ServerCertificateType,
            21 => ExtensionType::Padding,
            41 => ExtensionType::PreSharedKey,
            42 => ExtensionType::EarlyData,
            43 => ExtensionType::SupportedVersions,
            44 => ExtensionType::Cookie,
            45 => ExtensionType::PskKeyExchangeModes,
            47 => ExtensionType::CertificateAuthorities,
            48 => ExtensionType::OidFilters,
            49 => ExtensionType::PostHandshakeAuth,
            50 => ExtensionType::SignatureAlgorithmsCert,
            51 => ExtensionType::KeyShare,
            _ => {
                warn!("Unknown ExtensionType: {}", value);
                ExtensionType::ServerName
            }
        }
    }
}
/// `ExtensionData` is a wrapper for any data in the extension
/// TODO not all extension data types are implemented or added
#[derive(Debug, Clone)]
pub enum ExtensionData {
    ServerName(ServerNameList),
    SupportedGroups(NamedGroupList),
    SignatureAlgorithms(SupportedSignatureAlgorithms),
    SupportedVersions(SupportedVersions),
    KeyShareClientHello(KeyShareClientHello),
    KeyShareServerHello(KeyShareServerHello),
    PskKeyExchangeModes(PskKeyExchangeModes),
    Unserialized(Vec<u8>), // Placeholder for unimplemented extension data
}

impl ByteSerializable for ExtensionData {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            ExtensionData::ServerName(server_name_list) => server_name_list.as_bytes(),
            ExtensionData::SupportedGroups(named_group_list) => named_group_list.as_bytes(),
            ExtensionData::SignatureAlgorithms(supported_signature_algorithms) => {
                supported_signature_algorithms.as_bytes()
            }
            ExtensionData::SupportedVersions(supported_versions) => supported_versions.as_bytes(),
            ExtensionData::KeyShareClientHello(key_share_client_hello) => {
                key_share_client_hello.as_bytes()
            }
            ExtensionData::KeyShareServerHello(key_share_server_hello) => {
                key_share_server_hello.as_bytes()
            }
            ExtensionData::PskKeyExchangeModes(psk_key_exchange_modes) => {
                psk_key_exchange_modes.as_bytes()
            }
            ExtensionData::Unserialized(data) => Some(data.clone()),
        }
    }

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!()
    }
}

/// Kinds of `ProtocolVersion` - client offers multiple versions where a server selects one.
#[derive(Debug, Clone)]
pub enum VersionKind {
    Suggested(Vec<ProtocolVersion>), // length of the data can be 2..254 on client, 1 byte to present
    Selected(ProtocolVersion),
}

/// # Supported versions extension
#[derive(Debug, Clone)]
pub struct SupportedVersions {
    pub version: VersionKind,
}

impl ByteSerializable for SupportedVersions {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        match &self.version {
            VersionKind::Suggested(versions) => {
                for version in versions {
                    bytes.extend_from_slice(&version.to_be_bytes());
                }
                // 1 byte length determinant for `versions`
                bytes.splice(
                    0..0,
                    u8::try_from(bytes.len())
                        .ok()?
                        .to_be_bytes()
                        .iter()
                        .copied(),
                );
            }
            VersionKind::Selected(version) => {
                bytes.extend_from_slice(&version.to_be_bytes());
            }
        }
        Some(bytes)
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        // It takes at least 3 bytes to present ClientHello
        // Not the best for validation, but it's a start
        if bytes.len() > 2 {
            todo!("We don't support receiving ClientHello")
        } else {
            todo!("Serialize Selected variant")
        }
    }
}

/// Server Name extension, as defined in [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066#section-3)
/// `HostName` contains the fully qualified DNS hostname of the server,
/// as understood by the client.  The hostname is represented as a byte
/// string using ASCII encoding without a trailing dot.  This allows the
/// support of internationalized domain names through the use of A-labels
/// defined in RFC5890.  DNS hostnames are case-insensitive.  The
/// algorithm to compare hostnames is described in RFC5890, Section
/// 2.3.2.4.
#[derive(Debug, Clone)]
pub struct ServerName {
    pub name_type: NameType,
    pub host_name: HostName,
}
impl std::fmt::Display for ServerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = String::from_utf8_lossy(&self.host_name);
        writeln!(f, "{:?}: {}", self.name_type, name)
    }
}

/// `NameType` where maximum value be `u8::MAX` (1 byte)
#[derive(Debug, Copy, Clone)]
pub enum NameType {
    HostName = 0,
}
/// `HostName` is a byte string using ASCII encoding of host without a trailing dot
type HostName = Vec<u8>;
/// `ServerNameList` is a list of `ServerName` structures, where maximum length be `u16::MAX` (2 bytes)
#[derive(Debug, Clone)]
pub struct ServerNameList {
    pub server_name_list: Vec<ServerName>,
}
impl std::fmt::Display for ServerNameList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for server_name in &self.server_name_list {
            writeln!(f, "{server_name}")?;
        }
        Ok(())
    }
}

impl ByteSerializable for ServerNameList {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for server_name in &self.server_name_list {
            bytes.push(server_name.name_type as u8);
            // 2 byte length determinant for the ASCII byte presentation of the name
            bytes.extend_from_slice(
                u16::try_from(server_name.host_name.len())
                    .ok()?
                    .to_be_bytes()
                    .as_ref(),
            );
            bytes.extend_from_slice(&server_name.host_name);
        }
        // 2 byte length determinant for the whole `ServerNameList`
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

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement ServerNameList from_bytes")
    }
}

/// ## Signature Algorithm Extension
/// Our client primarily supports signature scheme Ed25519
/// Value takes 2 bytes to represent.
/// See more [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.3)
#[derive(Debug, Copy, Clone)]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,
    /* ECDSA algorithms */
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
    /* EdDSA algorithms */
    Ed25519 = 0x0807, // NOTE The only supported signature scheme
    Ed448 = 0x0808,
    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,
    /* Legacy algorithms */
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,
    /* Reserved Code Points */
    // PrivateUse(0xFE00..0xFFFF),
}
impl ByteSerializable for SignatureScheme {
    //noinspection DuplicatedCode
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match *self as u32 {
            #[allow(clippy::cast_possible_truncation)]
            value if u16::try_from(value).is_ok() => Some((value as u16).to_be_bytes().to_vec()),
            _ => None,
        }
    }

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement SignatureScheme from_bytes")
    }
}
#[derive(Debug, Clone)]
pub struct SupportedSignatureAlgorithms {
    pub supported_signature_algorithms: Vec<SignatureScheme>, // length of the data can be 2..2^16-2
}
impl ByteSerializable for SupportedSignatureAlgorithms {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for signature_scheme in &self.supported_signature_algorithms {
            bytes.extend_from_slice(&signature_scheme.as_bytes()?);
        }
        // 2 byte length determinant for the whole `SupportedSignatureAlgorithms`
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

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement SupportedSignatureAlgorithms from_bytes")
    }
}

/// ## Supported Groups Extension
/// Our client supports primarily Elliptic Curve Diffie-Hellman (ECDH) with Curve25519
/// Parameters for ECDH goes to opaque `key_exchange` field of a `KeyShareEntry` in a `KeyShare` structure.
/// Max size is (0xFFFF), takes 2 bytes to present
/// See more in [here.](https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.4)
#[derive(Debug, Copy, Clone)]
pub enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D, // NOTE The only supported named group
    X448 = 0x001E,
    /* Finite Field Groups (DHE) */
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
    /* Reserved Code Points */
    // ffdhe_private_use(0x01FC..0x01FF),
    // ecdhe_private_use(0xFE00..0xFEFF),
}
impl ByteSerializable for NamedGroup {
    //noinspection DuplicatedCode
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match *self as u32 {
            #[allow(clippy::cast_possible_truncation)]
            value if u16::try_from(value).is_ok() => Some((value as u16).to_be_bytes().to_vec()),
            _ => None,
        }
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        match bytes.get_u16().ok_or_else(ByteParser::insufficient_data)? {
            0x0017 => Ok(Box::new(NamedGroup::Secp256r1)),
            0x0018 => Ok(Box::new(NamedGroup::Secp384r1)),
            0x0019 => Ok(Box::new(NamedGroup::Secp521r1)),
            0x001D => Ok(Box::new(NamedGroup::X25519)),
            0x001E => Ok(Box::new(NamedGroup::X448)),
            0x0100 => Ok(Box::new(NamedGroup::Ffdhe2048)),
            0x0101 => Ok(Box::new(NamedGroup::Ffdhe3072)),
            0x0102 => Ok(Box::new(NamedGroup::Ffdhe4096)),
            0x0103 => Ok(Box::new(NamedGroup::Ffdhe6144)),
            0x0104 => Ok(Box::new(NamedGroup::Ffdhe8192)),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid NamedGroup",
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NamedGroupList {
    pub named_group_list: Vec<NamedGroup>, // (2 bytes to present)
}
impl ByteSerializable for NamedGroupList {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for named_group in &self.named_group_list {
            bytes.extend_from_slice(&named_group.as_bytes()?);
        }
        // 2 byte length determinant for `named_group_list`
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

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement NamedGroupList from_bytes")
    }
}

/// ## `KeyShare` Extension
#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>, // (2 bytes to present the length)
}
impl ByteSerializable for KeyShareEntry {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend(self.group.as_bytes()?);
        // 2 byte length determinant for the `key_exchange`
        bytes.extend(
            u16::try_from(self.key_exchange.len())
                .ok()?
                .to_be_bytes()
                .as_ref(),
        );
        bytes.extend_from_slice(&self.key_exchange);
        Some(bytes)
    }

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement KeyShareEntry from_bytes")
    }
}

/// There are three different structures for `KeyShare` extension
/// One for `ClientHello`, one for `HelloRetryRequest` and one for `ServerHello`
/// The order in the vector `KeyShareEntry` should be same as in `SupportedGroups` extension
#[derive(Debug, Clone)]
pub struct KeyShareClientHello {
    pub client_shares: Vec<KeyShareEntry>, // (2 bytes to present the length)
}

impl ByteSerializable for KeyShareClientHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for client_share in &self.client_shares {
            bytes.extend_from_slice(&client_share.as_bytes()?);
        }
        // 2 byte length determinant for `client_shares`
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

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement KeyShareClientHello from_bytes")
    }
}
/// `key_share` extension data structure in `ServerHello`
/// Contains only single `KeyShareEntry` when compared to `KeyShareClientHello`
#[derive(Debug, Clone)]
pub struct KeyShareServerHello {
    pub server_share: KeyShareEntry,
}
impl ByteSerializable for KeyShareServerHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        self.server_share.as_bytes()
    }

    fn from_bytes(bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        Ok(Box::new(KeyShareServerHello {
            server_share: *KeyShareEntry::from_bytes(bytes)?,
        }))
    }
}

/// Modes for pre-shared key (PSK) key exchange
/// Client-only
/// 1 byte to present
#[derive(Debug, Copy, Clone)]
pub enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
}
/// ## `psk_key_exchange_modes` extension
/// A client MUST provide a `PskKeyExchangeModes` extension if it
///  offers a `pre_shared_key` extension.
#[derive(Debug, Clone)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vec<PskKeyExchangeMode>, // (1 byte to present the length)
}

impl ByteSerializable for PskKeyExchangeModes {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for ke_mode in &self.ke_modes {
            bytes.push(*ke_mode as u8);
        }
        // 1 byte length determinant for `ke_modes`
        bytes.splice(
            0..0,
            u8::try_from(bytes.len())
                .ok()?
                .to_be_bytes()
                .iter()
                .copied(),
        );
        Some(bytes)
    }

    fn from_bytes(_bytes: &mut ByteParser) -> std::io::Result<Box<Self>> {
        todo!("Implement PskKeyExchangeModes from_bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_server_name_list() {
        let server_name_list = ServerNameList {
            server_name_list: vec![ServerName {
                name_type: NameType::HostName,
                host_name: "example.ulfheim.net".as_bytes().to_vec(),
            }],
        };
        let bytes = server_name_list.as_bytes().unwrap();
        assert_eq!(bytes.len(), 24);
        assert_eq!(
            bytes,
            vec![
                0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75,
                0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74
            ]
        );
    }
    #[test]
    fn test_extension_server_name_list() {
        let extension = Extension {
            origin: ExtensionOrigin::Client,
            extension_type: ExtensionType::ServerName,
            extension_data: ExtensionData::ServerName(ServerNameList {
                server_name_list: vec![ServerName {
                    name_type: NameType::HostName,
                    host_name: "example.ulfheim.net".as_bytes().to_vec(),
                }],
            }),
        };
        let bytes = extension.as_bytes().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70,
                0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74
            ]
        );
    }
}
