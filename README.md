# Spacer-Δ: Delta-Based Versioning for Unikernels

**Spacer-Δ** is a prototype tool for generating lightweight, delta-based versions of static libraries to enable efficient memory deduplication across multiple unikernel instances. It supports version-aware memory layouts that preserve alignment and sharing opportunities, while maintaining backward compatibility.

This tool is particularly useful in unikernel-based cloud environments where fine-grained memory sharing and performance isolation are critical.

This project is a **prototype** and is still under active development. It is not yet production-ready.

 📌 Examples and usage guides are coming soon.

#### Features:
- Generates delta object files by comparing ELF sections and symbols across versions
- Preserves cross-reference compatibility using trampoline tables
- Compatible with [Unikraft](https://github.com/unikraft/unikraft)-based environments

---

## 🧱 Project Structure

- `src/UkCommon.hpp`: Common utility functions and constants used across the Spacer-Δ tool, including ELF section/type and helper macros.
- `src/UkModifier.hpp`: Contains logic for modify symbol binding.
- `src/UkObjectFile.hpp`: Abstraction for reading, analyzing, and manipulating individual ELF object files using ELFIO++.
- `src/UkObjectManager.hpp`: Manages multiple UkObjectFile instances and coordinates version comparisons, delta generation, and symbol tracking.
- `src/UkReloSection.hpp`: Maps relocation to section.
- `src/UkRelocation.hpp`: Models an ELF relocation, including its content, alignment, and position. Provides logic to hash section.
- `src/UkSection.hpp`: Models an ELF section, including its content, alignment, and position. Provides logic to hash section.
- `src/UkSymbol.hpp`: Handles symbol entries and properties.
- `src/xxhash.hpp`: Header-only implementation of the xxHash algorithm for fast hashing. Used to detect identical function bodies or sections.

## 🛠️ Dependencies

Spacer-Δ depends on the following libraries:

- [`ELFIO`](https://github.com/serge1/ELFIO) (C++ ELF manipulation library)
- [`argparse`](https://github.com/p-ranav/argparse) (C++ argument parsing)
- [`spdlog`](https://github.com/gabime/spdlog) (Fast logging library)

You can install them with your system package manager or manually clone and build them.

## 🧪 Build and Run

Use the provided `Makefile` to build Spacer-Δ:

```bash
make
```

Then run it with:

```
Usage: spacer_delta [--help] [--version] [--workspace VAR] [--uksection VAR] [--log VAR] [--link VAR] [--uk_name VAR] [--sec_to_patch VAR] [--sec_to_globalize VAR] [--uk_version VAR]

Optional arguments:
  -h, --help          shows help message and exits
  -v, --version       prints version information and exits
  -w, --workspace     specify the workspace folder. [nargs=0..1] [default: "test/v1/"]
  -u, --uksection     specify the workspace folder. [nargs=0..1] [default: "lambda"]
  -l, --log           specify the log level. [nargs=0..1] [default: "info"]
  --link              specify the link file to use. [nargs=0..1] [default: "link64.lds"]
  --uk_name           The unikernel name to version (default: lib-lambda-v). [nargs=0..1] [default: "lib-lambda-v"]
  --sec_to_patch      Write in a file the modified sections to patch. [nargs=0..1] [default: "sec_to_patch.txt"]
  --sec_to_globalize  Write in a file the sections to globalize. [nargs=0..1] [default: "sec_to_globalize.txt"]
  --uk_version        The unikernel version to versionize (default: 2). [nargs=0..1] [default: 2]
```

## 🤝 License and Contributions

This project is licensed under the BSD 3-Clause License. See the LICENSE file for details.

Contributions, feedback, and suggestions are welcome. Feel free to open an issue or submit a pull request.