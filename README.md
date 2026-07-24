# PE-Any

[![Language](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6.svg?logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Made with](https://img.shields.io/badge/made%20by-zrnge.com-orange.svg)](https://zrnge.com)

A simple Win32 GUI tool for inspecting Portable Executable (PE) files.

**Developer:** [zrnge.com](https://zrnge.com)  
**Reference:** [zrnge.com/pe-any](https://zrnge.com/pe-any)  
**Repository:** [github.com/zrnge/pe-any](https://github.com/zrnge/pe-any)

---

## Features

- **General file info** — file size, entropy, SHA-256 hash
- **PE header analysis** — DOS header, NT headers, machine type, subsystem, entry point
- **Section table** — name, virtual size, raw size, characteristics for every section
- **Import table** — parsed imports with module and function names
- **Export table** — parsed exports with ordinals and function names
- **String extraction** — ASCII and Unicode strings found in the file
- **Hex dump** — raw hex view with ASCII sidebar
- **Tabbed GUI** — clean, native Win32 interface with tab navigation

---

## Screenshot

<!-- Add a screenshot here after running the tool -->
<!-- ![PE-Any Screenshot](screenshot.png) -->

---

## Building

### MinGW / GCC

```bash
gcc -O2 -o pe-any.exe pe-any.c -mwindows -lcomctl32 -lcomdlg32
```

### MSVC

```bash
cl /W3 /O2 pe-any.c /Fepe-any.exe user32.lib gdi32.lib comctl32.lib comdlg32.lib
```

---

## Usage

1. Run `pe-any.exe`
2. Click **Browse** to open any file (PE or otherwise)
3. Navigate the tabs to inspect different aspects of the file:
   - **General** — size, entropy, SHA-256
   - **PE Info** — headers, sections, directories
   - **Imports** — imported DLLs and functions
   - **Exports** — exported functions
   - **Strings** — extracted ASCII/Unicode strings
   - **Hex** — raw hex dump

---

## Requirements

- Windows (XP or later)
- No external dependencies — single-file C source, statically linked

---

## License

This project is provided as-is. See the source header for details.

---

## Related

- [zrnge.com](https://zrnge.com) — developer site
