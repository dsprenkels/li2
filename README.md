# Li2

Pure rust implementation of Dilithium, with custom assembly for acceleration.
Goals

* Be a _correct_, _open-source_, _maintained_ library implementing the
  Dilithium scheme.
* Should be importable into projects using Cargo.
* Also provides C exported functions (and header file)
* It should be _state-of-the-art_ in terms of:
  - Performance
  - Memory usage
  - Misuse resistant API (only Rust)
* First-class support for:
  - AVX2, Cortex-M4, Cortex-M3
* Second-class support for:
  - Cortex-M7, Cortex-M33
* Properly unit tested, regression tested, and vector-tested

## Short-term goals

* Construct a public C API wrapper and staticlib crate `li-clib`
  - Provide a NIST-competition compatible API under the 'nist-compatibility'
    feature flag
* In some way, ontegrate that static C libary into pqm4 and start benchmarking
* Get some kind of continuous integration going, for
  - Running formatting
  - Running tests
  - Testing benchmarks (?)
* Clean up the code; specifically the public-facing API

## Roadmap

* Ingegrate the optimizations from [BRS22]
* Integrate the optimizations from [GKS20] and [AHKS22]
* Integrate the optimizations from Seiler (avx2)
* Integrate the optimized butterfly optimization for Cortex-M3
* Integrate the new avx2 optimizations from Amber and Vincent
* Add support for dependency injection of an externally provided Keccak
  implementation

## Stretch goals

* Research aggressive batching of Keccak calls
* Add support for Dilithium ring signatures

## Why I am doing it

I am writing a Dilithium thesis, and I would like to consolidate all of my
results into a single implementation (they are now scattered across different
papers). I would like to use this implementation as the basis for all the
benchmarks that I am planning to put in the thesis.

## Why Rust

Rust is relatively easy to get as fast as C. However it has two main benefits
over C:

* Package management very streamlined. Much better than Makefiles/CMake/etc.
* Memory-safety guarantees are much better
* There have been a lot of C implementations, and not many Rust implementations
  that are "good".