# CHANGELOG

## v0.1.1

### Changes
- Optimize checking for windows reserved name.

### Fixes
- Windows reserved names are now case insensitive.

## v0.1.0
- Add reserved filenames with `WINDOWS_RESERVED` and `UNIX_RESERVED`. Platform
  specific option is `SYSTEM_RESERVED`.
- Add system mode enum `Mode`.
- Add function `allowed` to check if the given char is allowed in system mode.
- Add function `escape_str` to escape unique strings in the given system mode.
