use std::str::from_utf8;
use std::result::Result;
use nom::{IResult,eof};

/*
 * Core structs
 */

#[derive(Debug,PartialEq,Eq)]
pub struct TarEntry<'a> {
    pub header:   PosixHeader<'a>,
    pub contents: &'a str
}

#[derive(Debug,PartialEq,Eq)]
pub struct PosixHeader<'a> {
    pub name:     &'a str,
    pub mode:     &'a str,
    pub uid:      u64,
    pub gid:      u64,
    pub size:     u64,
    pub mtime:    u64,
    pub chksum:   &'a str,
    pub typeflag: TypeFlag,
    pub linkname: &'a str,
    pub ustar:    ExtraHeader<'a>
}

/* TODO: support vendor specific + sparse */
#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub enum TypeFlag {
    NormalFile,
    HardLink,
    SymbolicLink,
    CharacterSpecial,
    BlockSpecial,
    Directory,
    FIFO,
    ContiguousFile,
    PaxInterexchangeFormat,
    PaxExtendedAttributes,
    VendorSpecific
}

#[derive(Debug,PartialEq,Eq)]
pub enum ExtraHeader<'a> {
    UStar(UStarHeader<'a>),
    Padding
}

#[derive(Debug,PartialEq,Eq)]
pub struct UStarHeader<'a> {
    pub magic:    &'a str,
    pub version:  &'a str,
    pub uname:    &'a str,
    pub gname:    &'a str,
    pub devmajor: u64,
    pub devminor: u64,
    pub extra:    UStarExtraHeader<'a>
}

#[derive(Debug,PartialEq,Eq)]
pub enum UStarExtraHeader<'a> {
    PosixUStar(PosixUStarHeader<'a>),
    Pax(PaxHeader<'a>)
}

#[derive(Debug,PartialEq,Eq)]
pub struct PosixUStarHeader<'a> {
    pub prefix: &'a str
}

#[derive(Debug,PartialEq,Eq)]
pub struct PaxHeader<'a> {
    pub atime:         u64,
    pub ctime:         u64,
    pub offset:        u64,
    pub longnames:     &'a str,
    pub sparse:        [Sparse; 4],
    pub isextended:    bool,
    pub realsize:      u64,
    pub extra_sparses: Vec<Sparse>
}

#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub struct Sparse {
    pub offset:   u64,
    pub numbytes: u64
}

#[derive(Debug,PartialEq,Eq)]
pub struct Padding;

/*
 * Useful macros
 */

macro_rules! take_str_eat_garbage (
    ( $i:expr, $size:expr ) => (
        chain!($i,
            s: map_res!(take_until!("\0"), from_utf8) ~
            take!($size - s.len()),
            ||{
                s
            }
        )
    );
);

named!(parse_str4<&[u8], &str>, take_str_eat_garbage!(4));
named!(parse_str8<&[u8], &str>, take_str_eat_garbage!(8));
named!(parse_str32<&[u8], &str>, take_str_eat_garbage!(32));
named!(parse_str100<&[u8], &str>, take_str_eat_garbage!(100));
named!(parse_str155<&[u8], &str>, take_str_eat_garbage!(155));

/*
 * Octal string parsing
 */

pub fn octal_to_u64(s: &str) -> Result<u64, &'static str> {
    let mut u = 0;

    for c in s.chars() {
        if c < '0' || c > '7' {
            return Err("invalid octal string received");
        }
        u *= 8;
        u += (c as u64) - ('0' as u64);
    }

    Ok(u)
}

fn parse_octal(i: &[u8], n: usize) -> IResult<&[u8], u64> {
    map_res!(i, take_str_eat_garbage!(n), octal_to_u64)
}

named!(parse_octal8<&[u8], u64>, apply!(parse_octal, 8));
named!(parse_octal12<&[u8], u64>, apply!(parse_octal, 12));

/*
 * TypeFlag parsing
 */

fn char_to_type_flag(c: char) -> TypeFlag {
    match c {
        '0' | '\0' => TypeFlag::NormalFile,
        '1' => TypeFlag::HardLink,
        '2' => TypeFlag::SymbolicLink,
        '3' => TypeFlag::CharacterSpecial,
        '4' => TypeFlag::BlockSpecial,
        '5' => TypeFlag::Directory,
        '6' => TypeFlag::FIFO,
        '7' => TypeFlag::ContiguousFile,
        'g' => TypeFlag::PaxInterexchangeFormat,
        'x' => TypeFlag::PaxExtendedAttributes,
        'A' ... 'Z' => TypeFlag::VendorSpecific,
        _ => TypeFlag::NormalFile
    }
}

fn bytes_to_type_flag(i: &[u8]) -> Result<TypeFlag, &'static str> {
    Ok(char_to_type_flag(i[0] as char))
}

named!(parse_type_flag<&[u8], TypeFlag>, map_res!(take!(1), bytes_to_type_flag));

/*
 * Sparse parsing
 */

fn parse_one_sparse(i: &[u8]) -> IResult<&[u8], Sparse> {
    chain!(i,
        offset:   parse_octal12 ~
        numbytes: parse_octal12,
        ||{
            Sparse {
                offset:   offset,
                numbytes: numbytes
            }
        }
    )
}

fn parse_sparse(i: &[u8]) -> IResult<&[u8], [Sparse; 4]> {
    count!(i, parse_one_sparse, Sparse, 4)
}

fn add_to_vec(extra: [Sparse; 21], sparses: &mut Vec<Sparse>) -> Result<&'static str, &'static str> {
    for sparse in &extra[..] {
        if sparse.offset == 0 {
            break;
        } else {
            sparses.push(*sparse);
        }
    }
    Ok("")
}

fn parse_extra_sparses<'a>(i: &'a [u8], isextended: bool, sparses: &'a mut Vec<Sparse>) -> IResult<'a, &'a [u8], &'a mut Vec<Sparse>> {
    if isextended {
        chain!(i,
            map_res!(count!(parse_one_sparse, Sparse, 21), apply!(add_to_vec, sparses)) ~
            extended:      parse_bool                                                   ~
            take!(7) /* padding to 512 */                                               ~
            extra_sparses: apply!(parse_extra_sparses, extended, sparses),
            ||{
                extra_sparses
            }
        )
    } else {
        IResult::Done(i, sparses)
    }
}

/*
 * Boolean parsing
 */

fn to_bool(i: &[u8]) -> Result<bool, &'static str> {
    Ok(i[0] != 0)
}

named!(parse_bool<&[u8], bool>, map_res!(take!(1), to_bool));

/*
 * UStar PAX extended parsing
 */

fn parse_ustar00_extra_pax(i: &[u8]) -> IResult<&[u8], UStarExtraHeader> {
    let sparses : Vec<Sparse> = Vec::new();
    chain!(i,
        atime:         parse_octal12 ~
        ctime:         parse_octal12 ~
        offset:        parse_octal12 ~
        longnames:     parse_str4    ~
        take!(1)                     ~
        sparse:        parse_sparse  ~
        isextended:    parse_bool    ~
        realsize:      parse_octal12 ~
        take!(17)                    ~ /* padding to 512 */
        apply!(parse_extra_sparses, isextended, &mut sparses),
        ||{
            UStarExtraHeader::Pax(PaxHeader {
                atime:         atime,
                ctime:         ctime,
                offset:        offset,
                longnames:     longnames,
                sparse:        sparse,
                isextended:    isextended,
                realsize:      realsize,
                extra_sparses: sparses
            })
        }
    )
}

/*
 * UStar Posix parsing
 */

fn parse_ustar00_extra_posix(i: &[u8]) -> IResult<&[u8], UStarExtraHeader> {
    chain!(i,
        prefix: parse_str155 ~
        take!(12),
        ||{
            UStarExtraHeader::PosixUStar(PosixUStarHeader {
                prefix: prefix
            })
        }
    )
}

fn parse_ustar00_extra(i: &[u8], flag: TypeFlag) -> IResult<&[u8], UStarExtraHeader> {
    match flag {
        TypeFlag::PaxInterexchangeFormat => parse_ustar00_extra_pax(i),
        _ => parse_ustar00_extra_posix(i)
    }
}

fn parse_ustar00(i: &[u8], flag: TypeFlag) -> IResult<&[u8], ExtraHeader> {
    chain!(i,
        tag!("00")             ~
        uname:    parse_str32  ~
        gname:    parse_str32  ~
        devmajor: parse_octal8 ~
        devminor: parse_octal8 ~
        extra:    apply!(parse_ustar00_extra, flag),
        ||{
            ExtraHeader::UStar(UStarHeader {
                magic:    "ustar\0",
                version:  "00",
                uname:    uname,
                gname:    gname,
                devmajor: devmajor,
                devminor: devminor,
                extra:    extra
            })
        }
    )
}

fn parse_ustar(i: &[u8], flag: TypeFlag) -> IResult<&[u8], ExtraHeader> {
    chain!(i,
        tag!("ustar\0") ~
        ustar: apply!(parse_ustar00, flag),
        ||{
            ustar
        }
    )
}

/*
 * Posix tar archive header parsing
 */

fn parse_posix(i: &[u8]) -> IResult<&[u8], ExtraHeader> {
    chain!(i,
        take!(255), /* padding to 512 */
        ||{
            ExtraHeader::Padding
        }
    )
}

fn parse_header(i: &[u8]) -> IResult<&[u8], PosixHeader> {
    chain!(i,
        name:     parse_str100    ~
        mode:     parse_str8      ~
        uid:      parse_octal8    ~
        gid:      parse_octal8    ~
        size:     parse_octal12   ~
        mtime:    parse_octal12   ~
        chksum:   parse_str8      ~
        typeflag: parse_type_flag ~
        linkname: parse_str100    ~
        ustar:    alt!(apply!(parse_ustar, typeflag) | parse_posix),
        ||{
            PosixHeader {
                name:     name,
                mode:     mode,
                uid:      uid,
                gid:      gid,
                size:     size,
                mtime:    mtime,
                chksum:   chksum,
                typeflag: typeflag,
                linkname: linkname,
                ustar:    ustar
            }
        }
    )
}

/*
 * Contents parsing
 */

fn parse_contents(i: &[u8], size: u64) -> IResult<&[u8], &str> {
    let trailing = size % 512;
    let padding = match trailing {
        0 => 0,
        t => 512 - t
    };
    chain!(i,
        contents: take_str!(size as usize) ~
        take!(padding as usize),
        ||{
            contents
        }
    )
}

/*
 * Tar entry header + contents parsing
 */

fn parse_entry(i: &[u8]) -> IResult<&[u8], TarEntry> {
    chain!(i,
        header:   parse_header ~
        contents: apply!(parse_contents, header.size),
        ||{
            TarEntry {
                header: header,
                contents: contents
            }
        }
    )
}

/*
 * Tar archive parsing
 */

fn filter_entries(entries: Vec<TarEntry>) -> Result<Vec<TarEntry>, &'static str> {
    /* Filter out empty entries */
    Ok(entries.into_iter().filter(|e| e.header.name != "").collect::<Vec<TarEntry>>())
}

pub fn parse_tar(i: &[u8]) -> IResult<&[u8], Vec<TarEntry>> {
    chain!(i,
        entries: map_res!(many0!(parse_entry), filter_entries) ~
        eof,
        ||{
            entries
        }
    )
}

/*
 * Tests
 */

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::from_utf8;
    use nom::IResult;

    #[test]
    fn octal_to_u64_ok_test() {
        assert_eq!(octal_to_u64("756"), Ok(494));
        assert_eq!(octal_to_u64(""), Ok(0));
    }

    #[test]
    fn octal_to_u64_error_test() {
        assert_eq!(octal_to_u64("1238"), Err("invalid octal string received"));
        assert_eq!(octal_to_u64("a"), Err("invalid octal string received"));
        assert_eq!(octal_to_u64("A"), Err("invalid octal string received"));
    }

    #[test]
    fn take_str_eat_garbage_test() {
        let s = b"foobar\0\0\0\0baz";
        let baz = b"baz";
        assert_eq!(take_str_eat_garbage!(&s[..], 10), IResult::Done(&baz[..], "foobar"));
    }
}
