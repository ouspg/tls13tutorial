use crate::ProtocolVersion;

pub trait AsBytes {
    /// Returns `None` if the length of the data is out of standard constraints, otherwise returns `Some(Vec<u8>)`
    fn as_bytes(&self) -> Option<Vec<u8>>;
}

/// `Extension` is wrapper for any TLS extension
#[derive(Debug, Clone)]
pub struct Extension {
    pub extension_type: ExtensionType, // Defined maximum value can be 65535, takes 2 bytes to present
    pub extension_data: Vec<u8>,       // length of the data can be 0..2^16-1 (2 bytes to present)
}
impl AsBytes for Extension {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice((self.extension_type as u16).to_be_bytes().as_ref());
        // 2 byte length determinant for the `extension_data`
        bytes.extend_from_slice(
            u16::try_from(self.extension_data.len())
                .ok()?
                .to_be_bytes()
                .as_ref(),
        );
        bytes.extend_from_slice(&self.extension_data);
        Some(bytes)
    }
}

/// `ExtensionType` where maximum value be 2^16-1 (2 bytes to present)
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

#[derive(Debug, Clone)]
pub struct SupportedVersions {
    pub versions: Vec<ProtocolVersion>, // length of the data can be 2..254 on client, 1 byte to present
}
impl AsBytes for SupportedVersions {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for version in &self.versions {
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
        Some(bytes)
    }
}

/// Server Name extension, as defined in [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066#section-3)
/// `HostName` contains the fully qualified DNS hostname of the server,
/// as understood by the client.  The hostname is represented as a byte
/// string using ASCII encoding without a trailing dot.  This allows the
/// support of internationalized domain names through the use of A-labels
/// defined in [RFC5890].  DNS hostnames are case-insensitive.  The
/// algorithm to compare hostnames is described in [RFC5890], Section
/// 2.3.2.4.
#[derive(Debug, Clone)]
pub struct ServerName {
    pub name_type: NameType,
    pub name: Vec<u8>,
}
/// `NameType` where maximum value be `u8::MAX` (1 byte)
#[derive(Debug, Copy, Clone)]
pub enum NameType {
    HostName = 0,
}
type HostName = Vec<u8>;
/// `ServerNameList` is a list of `ServerName` structures, where maximum length be `u16::MAX` (2 bytes)
#[derive(Debug, Clone)]
pub struct ServerNameList {
    pub server_name_list: Vec<ServerName>,
}
impl AsBytes for ServerNameList {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for server_name in &self.server_name_list {
            bytes.push(server_name.name_type as u8);
            // 2 byte length determinant for the ASCII byte presentation of the name
            bytes.extend_from_slice(
                u16::try_from(server_name.name.len())
                    .ok()?
                    .to_be_bytes()
                    .as_ref(),
            );
            bytes.extend_from_slice(&server_name.name);
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
impl AsBytes for SignatureScheme {
    //noinspection DuplicatedCode
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match *self as u32 {
            #[allow(clippy::cast_possible_truncation)]
            value if u16::try_from(value).is_ok() => Some((value as u16).to_be_bytes().to_vec()),
            _ => None,
        }
    }
}
#[derive(Debug, Clone)]
pub struct SupportedSignatureAlgorithms {
    pub supported_signature_algorithms: Vec<SignatureScheme>, // length of the data can be 2..2^16-2
}
impl AsBytes for SupportedSignatureAlgorithms {
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
impl AsBytes for NamedGroup {
    //noinspection DuplicatedCode
    fn as_bytes(&self) -> Option<Vec<u8>> {
        match *self as u32 {
            #[allow(clippy::cast_possible_truncation)]
            value if u16::try_from(value).is_ok() => Some((value as u16).to_be_bytes().to_vec()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NamedGroupList {
    pub named_group_list: Vec<NamedGroup>, // (2 bytes to present)
}
impl AsBytes for NamedGroupList {
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
}

/// ## `KeyShare` Extension
#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>, // (2 bytes to present the length)
}
impl AsBytes for KeyShareEntry {
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
}

/// There are three different structures for `KeyShare` extension
/// One for `ClientHello`, one for `HelloRetryRequest` and one for `ServerHello`
/// The order in the vector `KeyShareEntry` should be same as in `SupportedGroups` extension
#[derive(Debug, Clone)]
pub struct KeyShareClientHello {
    pub client_shares: Vec<KeyShareEntry>, // (2 bytes to present the length)
}

impl AsBytes for KeyShareClientHello {
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
}
/// `key_share` extension data structure in `ServerHello`
/// Contains only single `KeyShareEntry` when compared to `KeyShareClientHello`
#[derive(Debug, Clone)]
pub struct KeyShareServerHello {
    pub server_share: KeyShareEntry,
}
impl AsBytes for KeyShareServerHello {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        self.server_share.as_bytes()
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
/// ## "psk_key_exchange_modes" extension
/// A client MUST provide a `PskKeyExchangeModes` extension if it
///  offers a "pre_shared_key" extension.
#[derive(Debug, Clone)]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vec<PskKeyExchangeMode>, // (1 byte to present the length)
}

impl AsBytes for PskKeyExchangeModes {
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
                name: "example.ulfheim.net".as_bytes().to_vec(),
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
            extension_type: ExtensionType::ServerName,
            extension_data: ServerNameList {
                server_name_list: vec![ServerName {
                    name_type: NameType::HostName,
                    name: "example.ulfheim.net".as_bytes().to_vec(),
                }],
            }
            .as_bytes()
            .unwrap(),
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
