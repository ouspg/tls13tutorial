//! `Display` trait implementations for various data structures.
//!
//! You probably do not need to modify this file, unless you want some pretty prints
use crate::extensions::ByteSerializable;
use crate::handshake::ClientHello;
use std::fmt::{self, Display, Formatter, Write};

/// Use output formatting similar as OpenSSL uses
impl Display for ClientHello {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let whole_len = self.as_bytes().ok_or(std::fmt::Error)?.len();
        let spaces_tier1 = 2;
        let spaces_tier2 = 4;
        // let spaces_tier3 = 6;
        writeln!(f, "ClientHello, Length={whole_len}")?;
        writeln!(
            f,
            "{:>width$}client_version=0x{:03X}",
            "",
            self.legacy_version,
            width = spaces_tier1,
        )?;
        writeln!(
            f,
            "{: >width$}random (len={}): {}",
            "",
            self.random.len(),
            to_hex(&self.random),
            width = spaces_tier1,
        )?;
        writeln!(
            f,
            "{: >width$}session_id (len={}): {}",
            "",
            self.legacy_session_id.len(),
            to_hex(&self.legacy_session_id),
            width = spaces_tier1,
        )?;
        writeln!(
            f,
            "{: >width$}cipher_suites (len={})",
            "",
            self.cipher_suites.len(),
            width = spaces_tier1,
        )?;
        for suite in &self.cipher_suites {
            writeln!(f, "{:>width$}{suite}", "", width = spaces_tier2)?;
        }
        writeln!(
            f,
            "{: >width$}compression_methods (len={}): {}",
            "",
            self.legacy_compression_methods.len(),
            to_hex(&self.legacy_compression_methods),
            width = spaces_tier1,
        )?;
        let ext_len = self
            .extensions
            .iter()
            .fold(0, |acc, ext| acc + ext.as_bytes().unwrap().len());
        writeln!(
            f,
            "{: >width$}extensions (len={ext_len})",
            "",
            width = spaces_tier1,
        )?;
        for ext in &self.extensions {
            writeln!(f, "{: >width$}{:?}\n", "", ext, width = spaces_tier2)?;
        }
        Ok(())
    }
}
/// Convert byte slice to hex string
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02X}");
        output
    })
}
