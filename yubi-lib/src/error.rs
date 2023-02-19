use core::fmt::{Display, Formatter};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum Error {
    Bug(String),
    PCSC(pcsc::Error),
    Verify(String),
    Apdu(String, u8, u8),
    Piv(String),
    Transport(String),
    Protocol(String),
    Arithmetic(String),
    NoKeys,
}

impl From<pcsc::Error> for Error {
    #[inline]
    fn from(value: pcsc::Error) -> Self {
        Self::PCSC(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Bug(e) => f.write_fmt(format_args!("BAD CODE ERROR: {e}")),
            Error::PCSC(e) => f.write_fmt(format_args!("PCSC ERROR: {e}")),
            Error::Verify(e) => f.write_fmt(format_args!("VERIFY ERROR: {e}")),
            Error::Apdu(e, sw1, sw2) => f.write_fmt(format_args!(
                "APDU ERROR: {e}, sw1 = {sw1:X?}, sw2 = {sw2:X?}"
            )),
            Error::Piv(e) => f.write_fmt(format_args!("PIV ERROR: {e}")),
            Error::Transport(e) => f.write_fmt(format_args!("TRANSPORT ERROR: {e}")),
            Error::Protocol(e) => f.write_fmt(format_args!("PROTOCOL ERROR: {e}")),
            Error::Arithmetic(e) => f.write_fmt(format_args!("ARITHMETIC ERROR: {e}")),
            Error::NoKeys => f.write_str("No keys found"),
        }
    }
}
