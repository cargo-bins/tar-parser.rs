use std::borrow::Cow;
use tar_parser2::*;

fn main() {
    let path = std::env::args_os().nth(1).unwrap();
    let file = std::fs::read(path).unwrap();
    let entries = parse_tar(&mut &*file).unwrap();
    let printer = TarPrinter::default();
    printer.print(&entries);
}

#[derive(Debug, Default)]
struct TarPrinter<'a> {
    longname: Option<Cow<'a, str>>,
    longlink: Option<&'a str>,
    realsize: Option<u64>,
}

impl<'a> TarPrinter<'a> {
    pub fn print(mut self, entries: &[TarEntry<'a>]) {
        for entry in entries {
            let typeflag = entry.header.typeflag;
            match typeflag {
                TypeFlag::HardLink | TypeFlag::SymbolicLink => {
                    let name = self.get_name(entry);
                    let target = self.longlink.take().unwrap_or(entry.header.linkname);
                    Self::print_link(typeflag, &name, target);
                }
                TypeFlag::GnuLongName => {
                    debug_assert!(entry.header.size > 1);
                    if let Ok(name) = parse_long_name(&mut &*entry.contents) {
                        debug_assert!(self.longname.is_none());
                        self.longname = Some(Cow::Borrowed(name));
                    }
                }
                TypeFlag::GnuLongLink => {
                    debug_assert!(entry.header.size > 1);
                    if let Ok(target) = parse_long_name(&mut &*entry.contents) {
                        debug_assert!(self.longlink.is_none());
                        self.longlink = Some(target);
                    }
                }
                TypeFlag::Pax => {
                    if let Ok(pax) = parse_pax(&mut &*entry.contents) {
                        if let Some(name) = pax.get("path") {
                            debug_assert!(self.longname.is_none());
                            self.longname = Some(Cow::Borrowed(name));
                        }
                        if let Some(target) = pax.get("linkpath") {
                            debug_assert!(self.longlink.is_none());
                            self.longlink = Some(target);
                        }
                        if let Some(size) = pax.get("size") {
                            debug_assert!(self.realsize.is_none());
                            self.realsize = size.parse().ok();
                        }
                    }
                }
                TypeFlag::PaxGlobal | TypeFlag::GnuVolumeHeader => {}
                _ => {
                    let name = self.get_name(entry);
                    let size = self.realsize.take().unwrap_or(entry.header.size);
                    Self::print_entry(typeflag, &name, size);
                }
            }
        }
    }

    fn get_name(&mut self, entry: &TarEntry<'a>) -> Cow<'a, str> {
        self.longname
            .take()
            .unwrap_or_else(|| Self::get_full_name(entry))
    }

    fn get_full_name(entry: &TarEntry<'a>) -> Cow<'a, str> {
        if let ExtraHeader::UStar(ustar) = &entry.header.ustar {
            if let UStarExtraHeader::Posix(header) = &ustar.extra {
                if !header.prefix.is_empty() {
                    return Cow::Owned(format!("{}/{}", header.prefix, entry.header.name));
                }
            }
        };
        Cow::Borrowed(entry.header.name)
    }

    fn print_entry(typeflag: TypeFlag, name: &str, size: u64) {
        let flag = Self::get_char_repr(typeflag);
        println!("{flag} {name} {size}");
    }

    fn print_link(typeflag: TypeFlag, name: &str, link: &str) {
        let flag = Self::get_char_repr(typeflag);
        println!("{flag} {name} -> {link}");
    }

    fn get_char_repr(typeflag: TypeFlag) -> char {
        match typeflag {
            TypeFlag::NormalFile | TypeFlag::ContiguousFile => 'F',
            TypeFlag::Directory | TypeFlag::GnuDirectory => 'D',
            TypeFlag::HardLink | TypeFlag::SymbolicLink => 'L',
            _ => '?',
        }
    }
}
