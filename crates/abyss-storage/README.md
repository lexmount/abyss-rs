# abyss-storage

Durable local SQLite primitives for the [Abyss endpoint runtime](https://github.com/lexmount/abyss-rs).

`SqliteStore` provides serialized Diesel connection access, database setup, and
local file permission handling. Callers own their table schemas, migrations,
and domain models. SQLite is bundled and compiled from source, so a native C
build toolchain is required; a separately installed SQLite library is not.

To install the standalone proxy, use `cargo install --locked abyss-broker`.
This crate is a library and does not install a command.

Licensed under GPL-3.0; see the included `LICENSE` file.
