//! A nom-based parser for TAR files.
//! This parser only accepts byte slice and doesn't deal with IO.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let file = std::fs::read("foo.tar")?;
//! # fn parse(file: &[u8]) -> Result<(), Box<dyn std::error::Error + '_>> {
//! let (_, entries) = tar_parser2::parse_tar(&file[..])?;
//! for entry in entries {
//!     println!("{}", entry.header.name);
//! }
//! # Ok(())
//! # }
//! # parse(&file[..]).unwrap();
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_until},
    character::complete::{digit1, oct_digit0, space0},
    combinator::{iterator, map, map_parser, map_res},
    error::ErrorKind,
    sequence::{pair, terminated},
    *,
};
use std::collections::HashMap;

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
    /// Header checksum.
    /// [`parse_tar`] doesn't check this field.
    pub chksum: &'a str,
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

fn parse_bool(i: &[u8]) -> IResult<&[u8], bool> {
    map(take(1usize), |i: &[u8]| i[0] != 0)(i)
}

/// Read null-terminated string and ignore the rest
/// If there's no null, `size` will be the length of the string.
fn parse_str(size: usize) -> impl FnMut(&[u8]) -> IResult<&[u8], &str> {
    move |input| {
        let s = map_res(alt((take_until("\0"), take(size))), std::str::from_utf8);
        map_parser(take(size), s)(input)
    }
}

macro_rules! impl_parse_str {
    ($($name:ident, $size:expr;)+) => ($(
        fn $name(i: &[u8]) -> IResult<&[u8], &str> {
            parse_str($size)(i)
        }
    )+)
}

impl_parse_str! {
    parse_str8, 8;
    parse_str32, 32;
    parse_str100, 100;
    parse_str155, 155;
}

/// Octal string parsing
fn parse_octal(i: &[u8], n: usize) -> IResult<&[u8], u64> {
    let (rest, input) = take(n)(i)?;
    let (i, value) = terminated(oct_digit0, space0)(input)?;

    if i.input_len() == 0 || i[0] == 0 {
        let value = value
            .iter()
            .fold(0, |acc, v| acc * 8 + u64::from(*v - b'0'));
        Ok((rest, value))
    } else {
        Err(nom::Err::Error(error_position!(i, ErrorKind::OctDigit)))
    }
}

fn parse_octal8(i: &[u8]) -> IResult<&[u8], u64> {
    parse_octal(i, 8)
}

fn parse_octal12(i: &[u8]) -> IResult<&[u8], u64> {
    parse_octal(i, 12)
}

/// [`TypeFlag`] parsing
fn parse_type_flag(i: &[u8]) -> IResult<&[u8], TypeFlag> {
    let (c, rest) = match i.split_first() {
        Some((c, rest)) => (c, rest),
        None => return Err(nom::Err::Incomplete(Needed::new(1))),
    };
    let flag = match c {
        b'0' | b'\0' => TypeFlag::NormalFile,
        b'1' => TypeFlag::HardLink,
        b'2' => TypeFlag::SymbolicLink,
        b'3' => TypeFlag::CharacterSpecial,
        b'4' => TypeFlag::BlockSpecial,
        b'5' => TypeFlag::Directory,
        b'6' => TypeFlag::Fifo,
        b'7' => TypeFlag::ContiguousFile,
        b'g' => TypeFlag::PaxGlobal,
        b'x' | b'X' => TypeFlag::Pax,
        b'D' => TypeFlag::GnuDirectory,
        b'K' => TypeFlag::GnuLongLink,
        b'L' => TypeFlag::GnuLongName,
        b'S' => TypeFlag::GnuSparse,
        b'V' => TypeFlag::GnuVolumeHeader,
        b'A'..=b'Z' => TypeFlag::VendorSpecific(*c),
        _ => return Err(nom::Err::Error(error_position!(i, ErrorKind::Fail))),
    };
    Ok((rest, flag))
}

/// [`Sparse`] parsing
fn parse_sparse(i: &[u8]) -> IResult<&[u8], Sparse> {
    let (i, (offset, numbytes)) = pair(parse_octal12, parse_octal12)(i)?;
    Ok((i, Sparse { offset, numbytes }))
}

fn parse_sparses(i: &[u8], count: usize) -> IResult<&[u8], Vec<Sparse>> {
    let mut it = iterator(i, parse_sparse);
    let res = it
        .take(count)
        .filter(|s| !(s.offset == 0 && s.numbytes == 0))
        .collect();
    let (i, ()) = it.finish()?;
    Ok((i, res))
}

fn add_to_vec(sparses: &mut Vec<Sparse>, extra: Vec<Sparse>) -> &mut Vec<Sparse> {
    sparses.extend(extra);
    sparses
}

fn parse_extra_sparses<'a, 'b>(
    i: &'a [u8],
    isextended: bool,
    sparses: &'b mut Vec<Sparse>,
) -> IResult<&'a [u8], &'b mut Vec<Sparse>> {
    if isextended {
        let (i, sps) = parse_sparses(i, 21)?;
        let (i, extended) = parse_bool(i)?;
        let (i, _) = take(7usize)(i)?; // padding to 512

        parse_extra_sparses(i, extended, add_to_vec(sparses, sps))
    } else {
        Ok((i, sparses))
    }
}

/// POSIX ustar extra header
fn parse_extra_posix(i: &[u8]) -> IResult<&[u8], UStarExtraHeader<'_>> {
    let (i, prefix) = terminated(parse_str155, take(12usize))(i)?;
    let header = UStarExtraHeader::Posix(PosixExtraHeader { prefix });
    Ok((i, header))
}

/// GNU ustar extra header
fn parse_extra_gnu(i: &[u8]) -> IResult<&[u8], UStarExtraHeader<'_>> {
    let mut sparses = Vec::new();

    let (i, atime) = parse_octal12(i)?;
    let (i, ctime) = parse_octal12(i)?;
    let (i, offset) = parse_octal12(i)?;
    let (i, _) = take(4usize)(i)?; // longnames
    let (i, _) = take(1usize)(i)?;
    let (i, sps) = parse_sparses(i, 4)?;
    let (i, isextended) = parse_bool(i)?;
    let (i, realsize) = parse_octal12(i)?;
    let (i, _) = take(17usize)(i)?; // padding to 512

    let (i, _) = parse_extra_sparses(i, isextended, add_to_vec(&mut sparses, sps))?;

    let header = GnuExtraHeader {
        atime,
        ctime,
        offset,
        sparses,
        realsize,
    };
    let header = UStarExtraHeader::Gnu(header);
    Ok((i, header))
}

/// Ustar general parser
fn parse_ustar(
    magic: &'static str,
    version: &'static str,
    mut extra: impl FnMut(&[u8]) -> IResult<&[u8], UStarExtraHeader>,
) -> impl FnMut(&[u8]) -> IResult<&[u8], ExtraHeader> {
    move |input| {
        let (i, _) = tag(magic)(input)?;
        let (i, _) = tag(version)(i)?;
        let (i, uname) = parse_str32(i)?;
        let (i, gname) = parse_str32(i)?;
        let (i, devmajor) = parse_octal8(i)?;
        let (i, devminor) = parse_octal8(i)?;
        let (i, extra) = extra(i)?;

        let header = ExtraHeader::UStar(UStarHeader {
            uname,
            gname,
            devmajor,
            devminor,
            extra,
        });
        Ok((i, header))
    }
}

/// Old header padding
fn parse_old(i: &[u8]) -> IResult<&[u8], ExtraHeader<'_>> {
    map(take(255usize), |_| ExtraHeader::Padding)(i) // padding to 512
}

fn parse_header(i: &[u8]) -> IResult<&[u8], TarHeader<'_>> {
    let (i, name) = parse_str100(i)?;
    let (i, mode) = parse_octal8(i)?;
    let (i, uid) = parse_octal8(i)?;
    let (i, gid) = parse_octal8(i)?;
    let (i, size) = parse_octal12(i)?;
    let (i, mtime) = parse_octal12(i)?;
    let (i, chksum) = parse_str8(i)?;
    let (i, typeflag) = parse_type_flag(i)?;
    let (i, linkname) = parse_str100(i)?;

    let (i, ustar) = alt((
        parse_ustar("ustar ", " \0", parse_extra_gnu),
        parse_ustar("ustar\0", "00", parse_extra_posix),
        parse_old,
    ))(i)?;

    let header = TarHeader {
        name,
        mode,
        uid,
        gid,
        size,
        mtime,
        chksum,
        typeflag,
        linkname,
        ustar,
    };
    Ok((i, header))
}

fn parse_contents(i: &[u8], size: u64) -> IResult<&[u8], &[u8]> {
    let trailing = size % 512;
    let padding = match trailing {
        0 => 0,
        t => 512 - t,
    };
    terminated(take(size), take(padding))(i)
}

fn parse_entry(i: &[u8]) -> IResult<&[u8], Option<TarEntry<'_>>> {
    {
        // Check if the header block is totally empty.
        let (i, block) = take(512usize)(i)?;
        if block == [0u8; 512] {
            return Ok((i, None));
        }
    }
    let (i, header) = parse_header(i)?;
    let (i, contents) = parse_contents(i, header.size)?;
    Ok((i, Some(TarEntry { header, contents })))
}

/// Parse the whole data as a TAR file, and return all entries.
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # static file: &[u8] = &[0];
/// use tar_parser2::*;
///
/// let (_, entries) = parse_tar(&file[..])?;
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
pub fn parse_tar(i: &[u8]) -> IResult<&[u8], Vec<TarEntry<'_>>> {
    let mut it = iterator(i, parse_entry);
    let entries = it.flatten().collect();
    let (i, ()) = it.finish()?;
    Ok((i, entries))
}

/// Parse GNU long pathname or linkname.
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # static file: &[u8] = &[0];
/// use tar_parser2::*;
///
/// let (_, entries) = parse_tar(&file[..])?;
/// let mut long_name = None;
/// for entry in entries {
///     if let TypeFlag::GnuLongName = entry.header.typeflag {
///         let (_, ln) = parse_long_name(entry.contents)?;
///         long_name = Some(ln);
///     } else {
///         let name = long_name.take().unwrap_or(entry.header.name);
///         println!("{}", name);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn parse_long_name(i: &[u8]) -> IResult<&[u8], &str> {
    parse_str(i.len())(i)
}

fn parse_pax_item(i: &[u8]) -> IResult<&[u8], (&str, &str)> {
    let (i, len) = map_res(terminated(digit1, tag(" ")), std::str::from_utf8)(i)?;
    let (i, key) = map_res(terminated(take_until("="), tag("=")), std::str::from_utf8)(i)?;
    let (i, value) = map_res(terminated(take_until("\n"), tag("\n")), std::str::from_utf8)(i)?;
    if let Ok(len_usize) = len.parse::<usize>() {
        debug_assert_eq!(len_usize, len.len() + key.len() + value.len() + 3);
    }
    Ok((i, (key, value)))
}

/// Parse PAX properties.
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # static file: &[u8] = &[0];
/// use tar_parser2::*;
///
/// let (_, entries) = parse_tar(&file[..])?;
/// let mut long_name = None;
/// for entry in entries {
///     if let TypeFlag::Pax = entry.header.typeflag {
///         let (_, prop) = parse_pax(entry.contents)?;
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
pub fn parse_pax(i: &[u8]) -> IResult<&[u8], HashMap<&str, &str>> {
    let mut it = iterator(i, parse_pax_item);
    let map = it.collect();
    let (i, ()) = it.finish()?;
    Ok((i, map))
}

#[cfg(test)]
mod parser_test {
    use crate::*;
    use nom::error::ErrorKind;

    const EMPTY: &[u8] = b"";

    #[test]
    fn parse_octal_ok_test() {
        assert_eq!(parse_octal(b"756", 3), Ok((EMPTY, 494)));
        assert_eq!(parse_octal(b"756\0 234", 8), Ok((EMPTY, 494)));
        assert_eq!(parse_octal(b"756    \0", 8), Ok((EMPTY, 494)));
        assert_eq!(parse_octal(b"", 0), Ok((EMPTY, 0)));
    }

    #[test]
    fn parse_octal_error_test() {
        let t1: &[u8] = b"1238";
        let _e: &[u8] = b"8";
        let t2: &[u8] = b"a";
        let t3: &[u8] = b"A";

        assert_eq!(
            parse_octal(t1, 4),
            Err(nom::Err::Error(error_position!(_e, ErrorKind::OctDigit)))
        );
        assert_eq!(
            parse_octal(t2, 1),
            Err(nom::Err::Error(error_position!(t2, ErrorKind::OctDigit)))
        );
        assert_eq!(
            parse_octal(t3, 1),
            Err(nom::Err::Error(error_position!(t3, ErrorKind::OctDigit)))
        );
    }

    #[test]
    fn parse_str_test() {
        let s: &[u8] = b"foobar\0\0\0\0baz";
        let baz: &[u8] = b"baz";
        assert_eq!(parse_str(10)(s), Ok((baz, "foobar")));
    }

    #[test]
    fn parse_sparses_test() {
        let sparses = std::iter::repeat(0u8).take(12 * 2 * 4).collect::<Vec<_>>();
        assert_eq!(parse_sparses(&sparses, 4), Ok((EMPTY, vec![])));
    }

    #[test]
    fn parse_pax_test() {
        let item: &[u8] = b"25 ctime=1084839148.1212\nfoo";
        let foo: &[u8] = b"foo";
        assert_eq!(
            parse_pax_item(item),
            Ok((foo, ("ctime", "1084839148.1212")))
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
        let (_, entries) = parse_tar(&buffer).unwrap();
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
        let (_, entries) = parse_tar(&buffer).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].header.typeflag, TypeFlag::GnuLongName);
        assert_eq!(parse_long_name(entries[0].contents).unwrap().1, &name);
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
        let (_, entries) = parse_tar(&buffer).unwrap();
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
