use std::{borrow::Cow, cmp, error, fmt};

use winnow::error::{AddContext, ErrMode, ErrorKind, FromExternalError, ParserError};

/// Accumulate context while backtracking errors
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    context: Vec<Cow<'static, str>>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl cmp::Eq for Error {}

impl cmp::PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.context == other.context
            && self.source.as_deref().map(|b| b as *const _)
                == other.source.as_deref().map(|b| b as *const _)
    }
}

impl Error {
    pub(super) fn new(context: impl Into<Cow<'static, str>>) -> ErrMode<Self> {
        ErrMode::Backtrack(Self {
            kind: ErrorKind::Fail,
            context: vec![context.into()],
            source: None,
        })
    }

    /// Access context from [`Parser::context`]
    pub fn context(&self) -> impl Iterator<Item = &Cow<'static, str>> {
        self.context.iter()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error kind: {}", self.kind)?;

        for context in &self.context {
            write!(f, ", context: {context}")?;
        }

        if let Some(source) = self.source.as_deref() {
            f.write_str(", source: ")?;
            // tailcall
            fmt::Display::fmt(source, f)
        } else {
            Ok(())
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn error::Error + 'static))
    }
}

impl<I> ParserError<I> for Error {
    fn from_error_kind(_input: &I, kind: ErrorKind) -> Self {
        Self {
            kind,
            context: Vec::new(),
            source: None,
        }
    }

    fn append(self, _input: &I, kind: ErrorKind) -> Self {
        Self {
            kind,
            context: Vec::new(),
            source: Some(Box::new(self)),
        }
    }
}

impl<C, I> AddContext<I, C> for Error
where
    C: Into<Cow<'static, str>>,
{
    fn add_context(mut self, _input: &I, ctx: C) -> Self {
        self.context.push(ctx.into());
        self
    }
}

impl<I, E: error::Error + Send + Sync + 'static> FromExternalError<I, E> for Error {
    #[inline]
    fn from_external_error(_input: &I, kind: ErrorKind, e: E) -> Self {
        Self {
            kind,
            context: Vec::new(),
            source: Some(Box::new(e)),
        }
    }
}
