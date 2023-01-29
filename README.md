# tar-parser

Implementation of a tar archive parser written in rust using nom.

``` rust
let file = std::fs::read("foo.tar")?;
let (_, entries) = tar_parser2::parse_tar(&file[..])?;
for entry in entries {
    println!("{}", entry.header.name);
}
```

For more robust example of listing TAR contents, see example `ls`.
