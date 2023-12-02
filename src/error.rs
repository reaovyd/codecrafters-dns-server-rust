use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to convert")]
    ConversionError,
    #[error("no specification for the implementation for conversion here yet")]
    UnimplementedError,

    #[error("too many bits. found {found:?}; overflow error")]
    OverflowError { found: u8 },
    #[error("section parsing failed")]
    SectionError,
    #[error("jump error during parsing")]
    JumpError,
}

#[derive(Debug, Error)]
pub enum UdpBufferError {
    #[error("EOB reached")]
    EndOfBuffer,
    #[error("could not reach the index requested; tried to reach {index:?}")]
    Seek { index: usize },
}
