use tar_parser2::*;

fn test_parse_tar(mut i: &[u8]) {
    match parse_tar(&mut i) {
        Ok(entries) => {
            for e in entries.iter() {
                println!("{e:?}");
            }
        }
        Err(e) => {
            println!("error or incomplete: {e:?}");
            panic!("cannot parse tar archive");
        }
    }
}

fn main() {
    let test = include_bytes!("simple/test.tar");
    let macos = include_bytes!("simple/macos.tar");
    let long = include_bytes!("simple/long.tar");
    println!("parse test");
    test_parse_tar(test);
    println!("parse macos");
    test_parse_tar(macos);
    println!("parse long");
    test_parse_tar(long);
}
