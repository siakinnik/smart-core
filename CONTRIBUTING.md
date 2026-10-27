# Contributing

Thanks for helping! Bug reports, ideas and pull requests are welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can
  agree on the approach.
- Code and comments are in English. C code is C99 without `malloc`, OS or
  platform headers in the core; platform code belongs in the device ports.
- Run the tests before opening a pull request:

  ```bash
  cmake -S . -B build -G Ninja && cmake --build build && ctest --test-dir build
  ```

- Protocol changes: properties and message fields are only ever appended.
  Update [PROTOCOL.md](PROTOCOL.md) in the same pull request.

## License and the CLA

The project is licensed under GPL-3.0-or-later. New source files start
with:

```c
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) <year> <your name>
```

Before your first pull request can be merged you sign the
[Contributor License Agreement](CLA.md). You keep the copyright in your
work; the agreement lets the maintainer also license it on other terms
(dual licensing), while the GPL version stays open for everyone. The CLA
bot explains how to sign right in the pull request: it's one comment, and
it covers all your future contributions.
