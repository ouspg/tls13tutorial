//! `Display` trait implementations for various data structures, including `ClientHello`, `Extension`.
//!
//! You probably do not need to modify this file, unless you want some additional pretty prints
use crate::extensions::{ByteSerializable, Extension, ExtensionType};
use crate::handshake::ClientHello;
use std::fmt::{self, Display, Formatter, Write};

const SPACES_TIER1: usize = 2;
const SPACES_TIER2: usize = 4;
const SPACES_TIER3: usize = 6;
/// Use output formatting similar as OpenSSL uses
impl Display for ClientHello {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let whole_len = self.as_bytes().ok_or(std::fmt::Error)?.len();
        // let spaces_tier3 = 6;
        writeln!(f, "ClientHello, Length={whole_len}")?;
        writeln!(
            f,
            "{:>width$}client_version=0x{:03X}",
            "",
            self.legacy_version,
            width = SPACES_TIER1,
        )?;
        writeln!(
            f,
            "{: >width$}random (len={}): {}",
            "",
            self.random.len(),
            to_hex(&self.random),
            width = SPACES_TIER1,
        )?;
        writeln!(
            f,
            "{: >width$}session_id (len={}): {}",
            "",
            self.legacy_session_id.len(),
            to_hex(&self.legacy_session_id),
            width = SPACES_TIER1,
        )?;
        writeln!(
            f,
            "{: >width$}cipher_suites (len={})",
            "",
            self.cipher_suites.len(),
            width = SPACES_TIER1,
        )?;
        for suite in &self.cipher_suites {
            writeln!(f, "{:>width$}{suite}", "", width = SPACES_TIER2)?;
        }
        writeln!(
            f,
            "{: >width$}compression_methods (len={}): {}",
            "",
            self.legacy_compression_methods.len(),
            to_hex(&self.legacy_compression_methods),
            width = SPACES_TIER1,
        )?;
        let ext_len = self
            .extensions
            .iter()
            .fold(0, |acc, ext| acc + ext.as_bytes().unwrap_or_default().len());
        writeln!(
            f,
            "{: >width$}extensions (len={ext_len})",
            "",
            width = SPACES_TIER1,
        )?;
        for ext in &self.extensions {
            writeln!(f, "{ext}")?;
        }
        Ok(())
    }
}

impl Display for ExtensionType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ExtensionType::ServerName => write!(f, "server_name({})", *self as u8),
            ExtensionType::MaxFragmentLength => write!(f, "max_fragment_length({})", *self as u8),
            ExtensionType::StatusRequest => write!(f, "status_request({})", *self as u8),
            ExtensionType::SupportedGroups => write!(f, "supported_groups({})", *self as u8),
            ExtensionType::SignatureAlgorithms => {
                write!(f, "signature_algorithms({})", *self as u8)
            }
            ExtensionType::UseSrtp => write!(f, "use_srtp({})", *self as u8),
            ExtensionType::Heartbeat => write!(f, "heartbeat({})", *self as u8),
            ExtensionType::ApplicationLayerProtocolNegotiation => {
                write!(f, "application_layer_protocol_negotiation({})", *self as u8)
            }
            ExtensionType::SignedCertificateTimestamp => {
                write!(f, "signed_certificate_timestamp({})", *self as u8)
            }
            ExtensionType::ClientCertificateType => {
                write!(f, "client_certificate_type({})", *self as u8)
            }
            ExtensionType::ServerCertificateType => {
                write!(f, "server_certificate_type({})", *self as u8)
            }
            ExtensionType::Padding => write!(f, "padding({})", *self as u8),
            ExtensionType::PreSharedKey => write!(f, "pre_shared_key({})", *self as u8),
            ExtensionType::EarlyData => write!(f, "early_data({})", *self as u8),
            ExtensionType::SupportedVersions => write!(f, "supported_versions({})", *self as u8),
            ExtensionType::Cookie => write!(f, "cookie({})", *self as u8),
            ExtensionType::PskKeyExchangeModes => {
                write!(f, "psk_key_exchange_modes({})", *self as u8)
            }
            ExtensionType::CertificateAuthorities => {
                write!(f, "certificate_authorities({})", *self as u8)
            }
            ExtensionType::OidFilters => write!(f, "oid_filters({})", *self as u8),
            ExtensionType::PostHandshakeAuth => write!(f, "post_handshake_auth({})", *self as u8),
            ExtensionType::SignatureAlgorithmsCert => {
                write!(f, "signature_algorithms_cert({})", *self as u8)
            }
            ExtensionType::KeyShare => write!(f, "key_share({})", *self as u8),
        }
    }
}

impl Display for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{:>width$}extension_type={}, length={}",
            "",
            self.extension_type,
            self.extension_data.as_bytes().ok_or(fmt::Error)?.len(),
            width = SPACES_TIER2
        )?;
        write!(
            f,
            "{:>width$}data: {}",
            "",
            to_hex(&self.extension_data.as_bytes().ok_or(fmt::Error)?),
            width = SPACES_TIER3
        )?;
        Ok(())
    }
}

/// Convert byte slice to hex string
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02X}");
        output
    })
}
