# Fuzzing

This repository supports libFuzzer-based fuzz targets for selected parsers and network message decoders.

## Supported toolchains

- Clang + libFuzzer (Linux recommended)
- `BUILD_FUZZING` is currently not supported on MSVC builds.

## Build

Example (Linux/macOS with Clang and Ninja):

```bash
cmake -S . -B build-fuzz -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTING=OFF \
  -DQRY_BUILD_BINARIES=OFF \
  -DBUILD_FUZZING=ON \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --parallel
```

## Run

Run each fuzzer for a short smoke test:

```bash
./build-fuzz/qrypt_fuzz_net_message_decode_fuzzer -max_total_time=30
./build-fuzz/qrypt_fuzz_tx_block_deserialize_fuzzer -max_total_time=30
```

For longer runs, increase `-max_total_time`, or provide a corpus directory:

```bash
mkdir -p corpus/net
./build-fuzz/qrypt_fuzz_net_message_decode_fuzzer corpus/net -max_total_time=600
```

## Adding a new fuzzer

- Add a new `*.cpp` file under `tests/fuzz/` exporting `LLVMFuzzerTestOneInput`.
- Keep harness logic minimal and prefer stable, well-scoped entry points (message decoders, deserializers, script parsers).
- Enforce bounded memory/time in harnesses for attacker-controlled sizes.

