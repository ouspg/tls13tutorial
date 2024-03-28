#![allow(clippy::module_name_repetitions)]
use crate::extensions::ByteSerializable;
use std::collections::VecDeque;
use std::io;
/// `AlertLevel` is a 1-byte value enum representing the level of the alert.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}
/// Allow textual representation of the alert level object
impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertLevel::Warning => write!(f, "Warning"),
            AlertLevel::Fatal => write!(f, "Fatal"),
        }
    }
}

/// `AlertDescription` is a 1-byte value enum representing the description of the alert.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPskIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtocol = 120,
}

/// Allow textual representation of the alert description object
impl std::fmt::Display for AlertDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertDescription::CloseNotify => write!(f, "CloseNotify"),
            AlertDescription::UnexpectedMessage => write!(f, "UnexpectedMessage"),
            AlertDescription::BadRecordMac => write!(f, "BadRecordMac"),
            AlertDescription::RecordOverflow => write!(f, "RecordOverflow"),
            AlertDescription::HandshakeFailure => write!(f, "HandshakeFailure"),
            AlertDescription::BadCertificate => write!(f, "BadCertificate"),
            AlertDescription::UnsupportedCertificate => write!(f, "UnsupportedCertificate"),
            AlertDescription::CertificateRevoked => write!(f, "CertificateRevoked"),
            AlertDescription::CertificateExpired => write!(f, "CertificateExpired"),
            AlertDescription::CertificateUnknown => write!(f, "CertificateUnknown"),
            AlertDescription::IllegalParameter => write!(f, "IllegalParameter"),
            AlertDescription::UnknownCa => write!(f, "UnknownCa"),
            AlertDescription::AccessDenied => write!(f, "AccessDenied"),
            AlertDescription::DecodeError => write!(f, "DecodeError"),
            AlertDescription::DecryptError => write!(f, "DecryptError"),
            AlertDescription::ProtocolVersion => write!(f, "ProtocolVersion"),
            AlertDescription::InsufficientSecurity => write!(f, "InsufficientSecurity"),
            AlertDescription::InternalError => write!(f, "InternalError"),
            AlertDescription::InappropriateFallback => write!(f, "InappropriateFallback"),
            AlertDescription::UserCanceled => write!(f, "UserCanceled"),
            AlertDescription::MissingExtension => write!(f, "MissingExtension"),
            AlertDescription::UnsupportedExtension => write!(f, "UnsupportedExtension"),
            AlertDescription::UnrecognizedName => write!(f, "UnrecognizedName"),
            AlertDescription::BadCertificateStatusResponse => {
                write!(f, "BadCertificateStatusResponse")
            }
            AlertDescription::UnknownPskIdentity => write!(f, "UnknownPskIdentity"),
            AlertDescription::CertificateRequired => write!(f, "CertificateRequired"),
            AlertDescription::NoApplicationProtocol => write!(f, "NoApplicationProtocol"),
        }
    }
}

/// `Alert` is a struct representing the whole alert message
#[derive(Debug, Clone, PartialEq, Eq)]

pub struct Alert {
    pub level: AlertLevel, // in TLS 1.3 the level is implicit and ignored
    pub description: AlertDescription,
}

impl ByteSerializable for Alert {
    fn as_bytes(&self) -> Option<Vec<u8>> {
        Some(vec![
            // Check that the values are within the u8 range
            u8::try_from(self.level as u16).ok()?,
            u8::try_from(self.description as u16).ok()?,
        ])
    }
    /// Parse the bytes into an `Alert` struct, data must be 2 bytes long
    fn from_bytes(bytes: &mut VecDeque<u8>) -> io::Result<Box<Alert>> {
        if bytes.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid alert length",
            ));
        }
        let level = match bytes.pop_front() {
            Some(1) => AlertLevel::Warning,
            Some(2) => AlertLevel::Fatal,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid alert level",
                ))
            }
        };
        let description = match bytes.pop_front() {
            Some(0) => AlertDescription::CloseNotify,
            Some(10) => AlertDescription::UnexpectedMessage,
            Some(20) => AlertDescription::BadRecordMac,
            Some(22) => AlertDescription::RecordOverflow,
            Some(40) => AlertDescription::HandshakeFailure,
            Some(42) => AlertDescription::BadCertificate,
            Some(43) => AlertDescription::UnsupportedCertificate,
            Some(44) => AlertDescription::CertificateRevoked,
            Some(45) => AlertDescription::CertificateExpired,
            Some(46) => AlertDescription::CertificateUnknown,
            Some(47) => AlertDescription::IllegalParameter,
            Some(48) => AlertDescription::UnknownCa,
            Some(49) => AlertDescription::AccessDenied,
            Some(50) => AlertDescription::DecodeError,
            Some(51) => AlertDescription::DecryptError,
            Some(70) => AlertDescription::ProtocolVersion,
            Some(71) => AlertDescription::InsufficientSecurity,
            Some(80) => AlertDescription::InternalError,
            Some(86) => AlertDescription::InappropriateFallback,
            Some(90) => AlertDescription::UserCanceled,
            Some(109) => AlertDescription::MissingExtension,
            Some(110) => AlertDescription::UnsupportedExtension,
            Some(112) => AlertDescription::UnrecognizedName,
            Some(113) => AlertDescription::BadCertificateStatusResponse,
            Some(115) => AlertDescription::UnknownPskIdentity,
            Some(116) => AlertDescription::CertificateRequired,
            Some(120) => AlertDescription::NoApplicationProtocol,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid alert description",
                ))
            }
        };
        Ok(Box::new(Alert { level, description }))
    }
}
/// Allow the textual presentation of the `Alert` struct
impl std::fmt::Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Alert of level {level}: {description}",
            level = self.level,
            description = self.description
        )
    }
}

#[cfg(test)]
mod tests {
    // Use the Alert types from the parent module
    use super::*;
    use crate::round_trip;

    #[test]
    // Test the conversion from bytes to Alert. Not comprehensive.
    fn test_alert_from_bytes() {
        let mut bytes = VecDeque::from([2, 50]);
        let alert = Alert::from_bytes(&mut bytes).unwrap();
        assert_eq!(alert.level, AlertLevel::Fatal);
        assert_eq!(alert.description, AlertDescription::DecodeError);
        let bytes = [1, 0];
        let mut bytes = VecDeque::from(bytes);
        let alert = Alert::from_bytes(&mut bytes).unwrap();
        assert_eq!(alert.level, AlertLevel::Warning);
        assert_eq!(alert.description, AlertDescription::CloseNotify);

        // With round_trip macro we can test encoding matches the expected value
        // And decoding results into the initial object
        // All of the above could be replaced with this approach
        round_trip!(
            Alert,
            Alert {
                level: AlertLevel::Fatal,
                description: AlertDescription::DecodeError
            },
            &[2, 50]
        );

        // ## Some negative testing ##

        // Invalid alert level
        let bytes = VecDeque::from([3, 0]);
        // We clone since the function consumes the bytes, and we make multiple calls
        assert!(Alert::from_bytes(&mut bytes.clone()).is_err());
        // More precise tests for specific error just to demonstrate the error handling
        assert!(matches!(
            Alert::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.kind() == io::ErrorKind::InvalidData
        ));
        assert!(matches!(
            Alert::from_bytes(&mut bytes.clone()),
            Err(ref e) if e.to_string() == "Invalid alert level"
        ));
        // Invalid alert description
        let mut bytes = VecDeque::from([1, 1]);
        assert!(Alert::from_bytes(&mut bytes).is_err());
        // Too long alert data
        let mut bytes = VecDeque::from([2, 50, 1]);
        assert!(Alert::from_bytes(&mut bytes).is_err());
    }
}
