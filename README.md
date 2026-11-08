# filesan
[![crates.io][version-badge]][package]
[![donwloads][downloads-badge]][releases]

Filename sanitizer.

Given a filename, uniquely escape the filename so that it is allowed by OS.

Supported OS:
- Windows
- Linux (unix)
- MAC

Generally the best function to use is `sanitize` which works on all systems
and guarantees unique outputs for unique inputs while staying human
understandable:
```rust
use filesan::sanitize;

assert_eq!(
    sanitize("\x00hello/the_re.txt:."),
    "_00hello_2Fthe_5Fre.txt_3A_2E"
);
```
But this crate provides more options for escaping filenames. For more info and
examples see [documentation][doc].

## Links
- **Author:** [BonnyAD9][author]
- **GitHub:** [BonnyAD9/filesan][github]
- **Package:** [crates.io][package]
- **Documentation:** [docs.rs][doc]
- **My Website:** [bonnyad9.github.io][my-web]

[doc]: https://docs.rs/filesan/latest/filesan/
[author]: https://github.com/BonnyAD9
[github]: https://github.com/BonnyAD9/filesan
[package]: https://crates.io/crates/filesan
[my-web]: https://bonnyad9.github.io/
[version-badge]: https://img.shields.io/crates/v/filesan
[downloads-badge]: https://img.shields.io/crates/d/filesan
[releases]: https://github.com/BonnyAD9/filesan/releases
