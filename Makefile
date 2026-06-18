# Default target builds; `make test` runs the suite. Keep `all` first: the
# collection's build gate builds the DEFAULT target of every commit.
CARGO ?= cargo

# METHOD hard rule 4: the build must be reproducible. This is the Rust
# spelling of -ffile-prefix-map, and it is a no-op for the binary as
# things stand: cargo invoked from the package directory already passes
# relative paths, and `strings` finds no absolute path in the release
# binary with or without it. It is here for the case where that stops
# being true, which is a build driven with an absolute --manifest-path.
# Measured rather than assumed: t/repro.sh builds the tree twice in two
# directories with different names and compares the binaries, and
# unrepro reports the binary identical both ways. What unrepro does flag
# is cargo's own bookkeeping under target/ (the .d dependency lists, the
# fingerprint files and .rustc_info.json), which is a build cache and
# not an output.
RUSTFLAGS ?= --remap-path-prefix=$(CURDIR)=.
export RUSTFLAGS

all:
	$(CARGO) build --release --offline

test: all
	sh t/run.sh

clean:
	$(CARGO) clean
	rm -rf t/corpus t/scratch

.PHONY: all test clean mutants overread hostile

# METHOD's buffer section, applied to Rust. The release profile is
# panic = abort, so a caught over-read gives exit 134, which is SIGABRT
# and is a status this program cannot produce any other way: its own
# codes are 0 for ok, 1 for a parse refusal, 2 for a usage error, 3 for a
# bad signature, 4 for an answer of no and 5 for a missing verifier.
#
# The target runs the SAME planted one-past-the-end read twice. Once
# against buffers that are exactly as long as their data, where it must be
# caught. Once with the decoder padding its output by 64 bytes, where it
# must NOT be caught, which is the demonstration that the bounds check is
# against the length of the Vec and not against the end of the data.
overread: all
	$(CARGO) build --release --offline --features plant_overread \
	    --target-dir target/overread
	$(CARGO) build --release --offline \
	    --features plant_overread,plant_slack \
	    --target-dir target/slack
	sh t/overread.sh
