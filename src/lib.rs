//! A nom-based parser for TAR files.
//! This parser only accepts byte slice and doesn't deal with IO.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let file = std::fs::read("foo.tar")?;
//! let entries = tar_parser2::parse_tar(&mut &file[..]).map_err(|err| err.into_inner().unwrap())?;
//! for entry in entries {
//!     println!("{}", entry.header.name);
//! }
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

use std::{collections::HashMap, str};
use winnow::{
    ascii::{digit1, oct_digit0, space0},
    combinator::{alt, iterator},
    error::ParserError,
    token::{tag, take, take_until0 as take_until},
    Parser,
};

mod error;
pub use error::Error;

/// Holds the result of parsers in this crate, re-export
/// of [`winnow::PResult`] with `E` set to [`Error`] by default.
pub type PResult<O, E = Error> = winnow::PResult<O, E>;

/// A tar entry. Maybe a file, a directory, or some extensions.
#[derive(Debug, PartialEq, Eq)]
pub struct TarEntry<'a> {
    /// Header of the entry.
    pub header: TarHeader<'a>,
    /// The content of the entry.
    /// You may need to call [`parse_long_name`] for GNU long name,
    /// or [`parse_pax`] for PAX properties.
    pub contents: &'a [u8],
}

/// A tar entry extracted using [`parse_entry_streaming`].
/// Maybe a file, a directory, or some extensions.
#[derive(Debug, PartialEq, Eq)]
pub struct TarEntryStreaming<'a> {
    /// Header of the entry.
    pub header: TarHeader<'a>,
    /// The size of header.
    /// To get the offset of the content,
    /// add this field to the offset of the header.
    ///
    /// You may need to call [`parse_long_name`] for GNU long name,
    /// or [`parse_pax`] for PAX properties.
    pub header_len: u64,
    /// Length of the content.
    pub content_len: u64,
    /// Padding after the content that needs to be ignored.
    pub padding_len: u64,
}

/// A tar header.
#[derive(Debug, PartialEq, Eq)]
pub struct TarHeader<'a> {
    /// The pathname of the entry.
    /// This field won't longer than 100 because of the structure.
    /// POSIX and GNU adds extensions for pathnames longer than 100.
    pub name: &'a str,
    /// File mode.
    pub mode: u64,
    /// User id of owner.
    pub uid: u64,
    /// Group id of owner.
    pub gid: u64,
    /// Size of file.
    pub size: u64,
    /// Modification time of file.
    /// Seconds since the epoch.
    pub mtime: u64,
    /// The type of entry.
    pub typeflag: TypeFlag,
    /// The link target of a link.
    /// If this entry is not a link, this field is empty.
    pub linkname: &'a str,
    /// The extra header.
    pub ustar: ExtraHeader<'a>,
}

/// Type of entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeFlag {
    /// Regular file.
    NormalFile,
    /// Hard link.
    HardLink,
    /// Symbolic link.
    SymbolicLink,
    /// Character device node.
    CharacterSpecial,
    /// Block device node.
    BlockSpecial,
    /// Directory.
    Directory,
    /// FIFO node.
    Fifo,
    /// Contiguous file, usually the same as regular file.
    ContiguousFile,
    /// Global PAX properties for all following regular entry.
    PaxGlobal,
    /// PAX properties for the following regular entry.
    Pax,
    /// GNU extension directory.
    /// It contains data records the names of files in this directory.
    GnuDirectory,
    /// GNU extension for long linkname for the following regular entry.
    GnuLongLink,
    /// GNU extension for long pathname for the following regular entry.
    GnuLongName,
    /// GNU extension for sparse regular file.
    GnuSparse,
    /// GNU extension for tape/volume header name.
    GnuVolumeHeader,
    /// Other vendor specific typeflag.
    VendorSpecific(u8),
}

/// Extra TAR header.
#[derive(Debug, PartialEq, Eq)]
pub enum ExtraHeader<'a> {
    /// Ustar header.
    UStar(UStarHeader<'a>),
    /// Padding to 512.
    Padding,
}

/// Ustar header.
#[derive(Debug, PartialEq, Eq)]
pub struct UStarHeader<'a> {
    /// User name.
    pub uname: &'a str,
    /// Group name.
    pub gname: &'a str,
    /// Major number for character device of block device.
    pub devmajor: u64,
    /// Minor number for character device of block device.
    pub devminor: u64,
    /// Extra header of ustar header.
    pub extra: UStarExtraHeader<'a>,
}

/// Extra header of ustar header.
#[derive(Debug, PartialEq, Eq)]
pub enum UStarExtraHeader<'a> {
    /// POSIX ustar extra header.
    Posix(PosixExtraHeader<'a>),
    /// GNU ustar extra header.
    Gnu(GnuExtraHeader),
}

/// POSIX ustar extra header.
/// See [`parse_tar`] for usage.
#[derive(Debug, PartialEq, Eq)]
pub struct PosixExtraHeader<'a> {
    /// First part of path name.
    /// If the pathname is longer than 100, it can be split at any `/`,
    /// with the first part going *here*.
    pub prefix: &'a str,
}

/// GNU ustar extra header.
#[derive(Debug, PartialEq, Eq)]
pub struct GnuExtraHeader {
    /// Last accessed time.
    pub atime: u64,
    /// Last change time.
    pub ctime: u64,
    /// Sparse offset.
    pub offset: u64,
    /// Sparse index blocks.
    pub sparses: Vec<Sparse>,
    /// Real file size.
    pub realsize: u64,
}

/// Sparse index block.
#[derive(Debug, PartialEq, Eq)]
pub struct Sparse {
    /// Offset of the block.
    pub offset: u64,
    /// Size of the block.
    pub numbytes: u64,
}

fn terminated<I, O1, O2, E, F, G>(first: F, second: G) -> impl Parser<I, O1, E>
where
    F: Parser<I, O1, E>,
    G: Parser<I, O2, E>,
    E: ParserError<I>,
{
    (first, second).map(|(o1, _)| o1)
}

fn parse_bool<'a>() -> impl Parser<&'a [u8], bool, Error> {
    take(1usize).map(|i: &[u8]| i[0] != 0)
}

/// Read null-terminated string and ignore the rest
/// If there's no null, `size` will be the length of the string.
fn parse_str<'a>(size: usize) -> impl Parser<&'a [u8], &'a str, Error> {
    let s = alt((take_until("\0"), take(size))).try_map(str::from_utf8);
    take(size).and_then(s)
}

/// Octal string parsing
fn parse_octal<'a>(n: usize) -> impl Parser<&'a [u8], u64, Error> {
    move |i: &mut &[u8]| {
        let mut input = take(n).parse_next(i)?;
        let value = terminated(oct_digit0, space0).parse_next(&mut input)?;

        if input.is_empty() || input[0] == 0 {
            let value = value
                .iter()
                .fold(0, |acc, v| acc * 8 + u64::from(*v - b'0'));
            Ok(value)
        } else {
            Err(Error::new("Expected octal digits with trailing spaces"))
        }
    }
}

/// [`TypeFlag`] parsing
fn parse_type_flag<'a>() -> impl Parser<&'a [u8], TypeFlag, Error> {
    |i: &mut &[u8]| {
        let slice = take(1_usize).parse_next(i)?;

        let c = slice[0];

        match c {
            b'0' | b'\0' => Ok(TypeFlag::NormalFile),
            b'1' => Ok(TypeFlag::HardLink),
            b'2' => Ok(TypeFlag::SymbolicLink),
            b'3' => Ok(TypeFlag::CharacterSpecial),
            b'4' => Ok(TypeFlag::BlockSpecial),
            b'5' => Ok(TypeFlag::Directory),
            b'6' => Ok(TypeFlag::Fifo),
            b'7' => Ok(TypeFlag::ContiguousFile),
            b'g' => Ok(TypeFlag::PaxGlobal),
            b'x' | b'X' => Ok(TypeFlag::Pax),
            b'D' => Ok(TypeFlag::GnuDirectory),
            b'K' => Ok(TypeFlag::GnuLongLink),
            b'L' => Ok(TypeFlag::GnuLongName),
            b'S' => Ok(TypeFlag::GnuSparse),
            b'V' => Ok(TypeFlag::GnuVolumeHeader),
            b'A'..=b'Z' => Ok(TypeFlag::VendorSpecific(c)),
            _ => Err(Error::new("Unexpected flag value")),
        }
    }
}

/// [`Sparse`] parsing
fn parse_sparse<'a>() -> impl Parser<&'a [u8], Sparse, Error> {
    (parse_octal(12), parse_octal(12)).map(|(offset, numbytes)| Sparse { offset, numbytes })
}

fn parse_sparses_iter<C, T>(count: usize, i: &mut &[u8], callback: C) -> PResult<T>
where
    C: FnOnce(&mut dyn Iterator<Item = Sparse>) -> T,
{
    let mut it = iterator(*i, parse_sparse());

    let res = callback(
        &mut it
            .take(count)
            .filter(|s| !(s.offset == 0 && s.numbytes == 0)),
    );

    *i = it.finish()?.0;

    Ok(res)
}

fn parse_sparses<'a>(count: usize) -> impl Parser<&'a [u8], Vec<Sparse>, Error> {
    move |i: &mut &[u8]| parse_sparses_iter(count, i, |it| it.collect())
}

fn parse_extra_sparses<'a>(sparses: &mut Vec<Sparse>) -> impl Parser<&'a [u8], (), Error> + '_ {
    move |i: &mut &[u8]| {
        loop {
            parse_sparses_iter(21, i, |it| sparses.extend(it))?;
            let extended = parse_bool().parse_next(i)?;
            take(7usize).parse_next(i)?; // padding to 512

            if !extended {
                break Ok(());
            }
        }
    }
}

/// POSIX ustar extra header
fn parse_extra_posix<'a>() -> impl Parser<&'a [u8], UStarExtraHeader<'a>, Error> {
    terminated(parse_str(155), take(12usize))
        .map(|prefix| UStarExtraHeader::Posix(PosixExtraHeader { prefix }))
}

/// GNU ustar extra header
fn parse_extra_gnu<'a>() -> impl Parser<&'a [u8], UStarExtraHeader<'a>, Error> {
    |i: &mut &[u8]| {
        let atime = parse_octal(12).parse_next(i)?;
        let ctime = parse_octal(12).parse_next(i)?;
        let offset = parse_octal(12).parse_next(i)?;
        take(4usize).parse_next(i)?; // longnames
        take(1usize).parse_next(i)?;
        let mut sparses = parse_sparses(4).parse_next(i)?;
        let isextended = parse_bool().parse_next(i)?;
        let realsize = parse_octal(12).parse_next(i)?;
        take(17usize).parse_next(i)?; // padding to 512

        if isextended {
            parse_extra_sparses(&mut sparses).parse_next(i)?;
        }

        Ok(UStarExtraHeader::Gnu(GnuExtraHeader {
            atime,
            ctime,
            offset,
            sparses,
            realsize,
        }))
    }
}

/// Ustar general parser
fn parse_ustar<'a>(
    magic: &'static str,
    version: &'static str,
    extra: impl Parser<&'a [u8], UStarExtraHeader<'a>, Error>,
) -> impl Parser<&'a [u8], ExtraHeader<'a>, Error> {
    (
        tag(magic),
        tag(version),
        parse_str(32),
        parse_str(32),
        parse_octal(8),
        parse_octal(8),
        extra,
    )
        .map(|(_, _, uname, gname, devmajor, devminor, extra)| {
            ExtraHeader::UStar(UStarHeader {
                uname,
                gname,
                devmajor,
                devminor,
                extra,
            })
        })
}

/// Old header padding
fn parse_old<'a>() -> impl Parser<&'a [u8], ExtraHeader<'a>, Error> {
    take(255usize).map(|_| ExtraHeader::Padding) // padding to 512
}

fn parse_header<'a>(i: &mut &'a [u8]) -> PResult<TarHeader<'a>> {
    debug_assert!(i.len() >= 512);

    let header_chksum = i[..148].iter().map(|b| *b as u64).sum::<u64>()
        + i[156..512].iter().map(|b| *b as u64).sum::<u64>()
        + 8 * (b' ' as u64);
    let name = parse_str(100).parse_next(i)?;
    let mode = parse_octal(8).parse_next(i)?;
    let uid = parse_octal(8).parse_next(i)?;
    let gid = parse_octal(8).parse_next(i)?;
    let size = parse_octal(12).parse_next(i)?;
    let mtime = parse_octal(12).parse_next(i)?;
    let chksum = parse_octal(8).parse_next(i)?;
    if header_chksum != chksum {
        return Err(Error::new("Mismatched checksum!"));
    }
    let typeflag = parse_type_flag().parse_next(i)?;
    let linkname = parse_str(100).parse_next(i)?;

    let ustar = alt((
        parse_ustar("ustar ", " \0", parse_extra_gnu()),
        parse_ustar("ustar\0", "00", parse_extra_posix()),
        parse_old(),
    ))
    .parse_next(i)?;

    Ok(TarHeader {
        name,
        mode,
        uid,
        gid,
        size,
        mtime,
        typeflag,
        linkname,
        ustar,
    })
}

/// Tries to parse the data and extract a tar entry.
///
/// This can be used to implement streaming mode parsing,
/// which can use with sync reader such as `std::io::Read`,
/// or async reader such as `tokio::io::AsyncRead`.
pub fn parse_entry_streaming<'a>(i: &mut &'a [u8]) -> PResult<Option<TarEntryStreaming<'a>>> {
    let len = i.len();

    {
        let mut i = *i;
        if i.is_empty() {
            return Ok(None);
        }
        // Check if the header block is totally empty.
        let block = take(512usize).parse_next(&mut i)?;
        if block.iter().all(|x| *x == 0) {
            return Ok(None);
        }
    }
    let header = parse_header(i)?;

    let header_len = (len - i.len()) as u64;
    let content_len = header.size;
    let padding_len = match content_len % 512 {
        0 => 0,
        t => 512 - t,
    };
    Ok(Some(TarEntryStreaming {
        header,
        header_len,
        content_len,
        padding_len,
    }))
}

fn parse_entry<'a>(i: &mut &'a [u8]) -> PResult<Option<TarEntry<'a>>> {
    let entry = parse_entry_streaming(i)?;
    if let Some(entry) = entry {
        let contents = terminated(
            take(entry.content_len as usize),
            take(entry.padding_len as usize),
        )
        .parse_next(i)?;
        Ok(Some(TarEntry {
            header: entry.header,
            contents,
        }))
    } else {
        Ok(None)
    }
}

/// Parse the whole data as a TAR file, and return all entries.
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # static file: &[u8] = &[0];
/// use tar_parser2::*;
///
/// let entries = parse_tar(&mut &file[..]).map_err(|err| err.into_inner().unwrap())?;
/// for entry in entries {
///     let mut name = entry.header.name.to_string();
///     if let ExtraHeader::UStar(extra) = entry.header.ustar {
///         if let UStarExtraHeader::Posix(extra) = extra.extra {
///             if !extra.prefix.is_empty() {
///                 name = format!("{}/{}", extra.prefix, name);
///             }
///         }
///     }
///     println!("{}", name);
/// }
/// # Ok(())
/// # }
/// ```
pub fn parse_tar<'a>(i: &mut &'a [u8]) -> PResult<Vec<TarEntry<'a>>> {
    let mut it = iterator(*i, parse_entry);

    let mut entries = Vec::with_capacity(1);
    for each in &mut it {
        if let Some(entry) = each {
            entries.push(entry);
        } else {
            break;
        }
    }
    *i = it.finish()?.0;
    Ok(entries)
}

/// Parse GNU long pathname or linkname.
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # static file: &[u8] = &[0];
/// use tar_parser2::*;
///
/// let entries = parse_tar(&mut &file[..]).map_err(|err| err.into_inner().unwrap())?;
/// let mut long_name = None;
/// for entry in entries {
///     if let TypeFlag::GnuLongName = entry.header.typeflag {
///         let ln = parse_long_name(&mut &*entry.contents).map_err(|err| err.into_inner().unwrap())?;
///         long_name = Some(ln);
///     } else {
///         let name = long_name.take().unwrap_or(entry.header.name);
///         println!("{}", name);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn parse_long_name<'a>(i: &mut &'a [u8]) -> PResult<&'a str> {
    parse_str(i.len()).parse_next(i)
}

fn parse_pax_item<'a>() -> impl Parser<&'a [u8], (&'a str, &'a str), Error> {
    |i: &mut &'a [u8]| -> PResult<(&'a str, &'a str)> {
        let (len_str, key, value) = (
            terminated(digit1, tag(" ")).try_map(str::from_utf8),
            terminated(take_until("="), tag("=")).try_map(str::from_utf8),
            terminated(take_until("\n"), tag("\n")).try_map(str::from_utf8),
        )
            .parse_next(i)?;

        let msg_len = len_str.len() + key.len() + value.len() + 3;
        match len_str.parse::<usize>() {
            Ok(len_usize) if len_usize != msg_len => Err(Error::new(format!(
                "Invalid pax item: Expected {len_usize} bytes pax message, found {msg_len} bytes"
            ))),
            Err(err) => Err(Error::new(format!(
                "Failed to parse pax message len: {err}"
            ))),
            _ => Ok((key, value)),
        }
    }
}

/// Parse PAX properties.
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # static file: &[u8] = &[0];
/// use tar_parser2::*;
///
/// let entries = parse_tar(&mut &file[..]).map_err(|err| err.into_inner().unwrap())?;
/// let mut long_name = None;
/// for entry in entries {
///     if let TypeFlag::Pax = entry.header.typeflag {
///         let prop = parse_pax(&mut &*entry.contents).map_err(|err| err.into_inner().unwrap())?;
///         // Map to make borrow checker happy.
///         long_name = prop.get("path").map(|s| *s);
///     } else {
///         let name = long_name.take().unwrap_or(entry.header.name);
///         println!("{}", name);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn parse_pax<'a>(i: &mut &'a [u8]) -> PResult<HashMap<&'a str, &'a str>> {
    let mut it = iterator(*i, parse_pax_item());
    let map = it.collect();
    *i = it.finish()?.0;
    Ok(map)
}

#[cfg(test)]
mod parser_test {
    use super::*;

    const EMPTY: &[u8] = b"";

    #[test]
    fn parse_octal_ok_test() {
        assert_eq!(parse_octal(3).parse_peek(b"756").unwrap(), (EMPTY, 494));
        assert_eq!(
            parse_octal(8).parse_peek(b"756\0 234").unwrap(),
            (EMPTY, 494)
        );
        assert_eq!(
            parse_octal(8).parse_peek(b"756    \0").unwrap(),
            (EMPTY, 494)
        );
        assert_eq!(parse_octal(0).parse_peek(b"").unwrap(), (EMPTY, 0));
    }

    #[test]
    fn parse_octal_error_test() {
        let t1: &[u8] = b"1238";
        let _e: &[u8] = b"8";
        let t2: &[u8] = b"a";
        let t3: &[u8] = b"A";

        assert_eq!(
            parse_octal(4).parse_peek(t1).unwrap_err(),
            Error::new("Expected octal digits with trailing spaces")
        );
        assert_eq!(
            parse_octal(1).parse_peek(t2).unwrap_err(),
            Error::new("Expected octal digits with trailing spaces")
        );
        assert_eq!(
            parse_octal(1).parse_peek(t3).unwrap_err(),
            Error::new("Expected octal digits with trailing spaces")
        );
    }

    #[test]
    fn parse_str_test() {
        let s: &[u8] = b"foobar\0\0\0\0baz";
        let baz: &[u8] = b"baz";
        assert_eq!(parse_str(10).parse_peek(s).unwrap(), (baz, "foobar"));
    }

    #[test]
    fn parse_sparses_test() {
        let sparses = std::iter::repeat(0u8).take(12 * 2 * 4).collect::<Vec<_>>();
        assert_eq!(
            parse_sparses(4).parse_peek(&sparses,).unwrap(),
            (EMPTY, vec![])
        );
    }

    #[test]
    fn parse_pax_test() {
        let item: &[u8] = b"25 ctime=1084839148.1212\nfoo";
        let foo: &[u8] = b"foo";
        assert_eq!(
            parse_pax_item().parse_peek(item).unwrap(),
            (foo, ("ctime", "1084839148.1212"))
        );
    }
}

#[cfg(test)]
mod tar_test {
    use crate::*;
    use std::io::{Read, Seek};
    use tempfile::tempfile;

    const LIB_RS_FILE: &str = "src/lib.rs";

    #[test]
    fn basic() {
        let file = tempfile().unwrap();
        let mut archive = tar::Builder::new(file);
        archive
            .append_path_with_name(LIB_RS_FILE, "lib.rs")
            .unwrap();
        let mut file = archive.into_inner().unwrap();
        file.rewind().unwrap();

        let mut buffer = vec![];
        file.read_to_end(&mut buffer).unwrap();
        let entries = parse_tar(&mut &*buffer).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.typeflag, TypeFlag::NormalFile);
        assert_eq!(entries[0].header.name, "lib.rs");
        assert_eq!(entries[0].contents, std::fs::read(LIB_RS_FILE).unwrap());
    }

    #[test]
    fn gnu_long() {
        let name = "a".repeat(1024);

        let file = tempfile().unwrap();
        let mut archive = tar::Builder::new(file);
        archive.append_path_with_name(LIB_RS_FILE, &name).unwrap();
        let mut file = archive.into_inner().unwrap();
        file.rewind().unwrap();

        let mut buffer = vec![];
        file.read_to_end(&mut buffer).unwrap();
        let entries = parse_tar(&mut &*buffer).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].header.typeflag, TypeFlag::GnuLongName);
        assert_eq!(parse_long_name(&mut &*entries[0].contents).unwrap(), &name);
        assert_eq!(entries[1].contents, std::fs::read(LIB_RS_FILE).unwrap());
    }

    #[test]
    fn posix_long() {
        let name_prefix = "a".repeat(80);
        let name_postfix = "b".repeat(80);
        let name = format!("{name_prefix}/{name_postfix}");

        let file = tempfile().unwrap();
        let mut archive = tar::Builder::new(file);
        {
            let mut header = tar::Header::new_ustar();
            let file = std::fs::File::open(LIB_RS_FILE).unwrap();
            let size = file.metadata().unwrap().len();
            header.set_size(size);
            archive.append_data(&mut header, name, file).unwrap();
        }
        let mut file = archive.into_inner().unwrap();
        file.rewind().unwrap();

        let mut buffer = vec![];
        file.read_to_end(&mut buffer).unwrap();
        let entries = parse_tar(&mut &*buffer).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.typeflag, TypeFlag::NormalFile);
        assert_eq!(entries[0].header.name, name_postfix);
        if let ExtraHeader::UStar(extra) = &entries[0].header.ustar {
            if let UStarExtraHeader::Posix(extra) = &extra.extra {
                assert_eq!(extra.prefix, name_prefix);
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        }
        assert_eq!(entries[0].contents, std::fs::read(LIB_RS_FILE).unwrap());
    }
}
