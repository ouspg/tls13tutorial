use std::io;
/// `AlertLevel` is a 1-byte value enum representing the level of the alert.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}
/// Allow text representation of the alert level object
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
enum AlertDescription {
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
    level: AlertLevel,
    description: AlertDescription,
}

impl Alert {
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Alert> {
        if bytes.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid alert length",
            ));
        }
        let level = match bytes[0] {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid alert level",
                ))
            }
        };
        let description = match bytes[1] {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            22 => AlertDescription::RecordOverflow,
            40 => AlertDescription::HandshakeFailure,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            86 => AlertDescription::InappropriateFallback,
            90 => AlertDescription::UserCanceled,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            112 => AlertDescription::UnrecognizedName,
            113 => AlertDescription::BadCertificateStatusResponse,
            115 => AlertDescription::UnknownPskIdentity,
            116 => AlertDescription::CertificateRequired,
            120 => AlertDescription::NoApplicationProtocol,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid alert description",
                ))
            }
        };
        Ok(Alert { level, description })
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
    use super::*;

    #[test]
    // Test the conversion from bytes to Alert. Not comprehensive.
    fn test_alert_from_bytes() {
        let bytes = [2, 50];
        let alert = Alert::from_bytes(&bytes).unwrap();
        assert_eq!(alert.level, AlertLevel::Fatal);
        assert_eq!(alert.description, AlertDescription::DecodeError);
        let bytes = [1, 0];
        let alert = Alert::from_bytes(&bytes).unwrap();
        assert_eq!(alert.level, AlertLevel::Warning);
        assert_eq!(alert.description, AlertDescription::CloseNotify);
        // Invalid alert level
        let bytes = [3, 0];
        assert!(Alert::from_bytes(&bytes).is_err());
        // Invalid alert description
        let bytes = [1, 1];
        assert!(Alert::from_bytes(&bytes).is_err());
        // Too long alert data
        let bytes = [2, 50, 1];
        assert!(Alert::from_bytes(&bytes).is_err());
    }
}
