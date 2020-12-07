# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  # Standard library
  unittest,
  # internal
  ../blscurve/openmp,
  # Public API
  ../blscurve

# Tests for batch verification
# Compile with -d:openmp for parallel tests
proc omp_status(): string =
  when defined(openmp):
    "[Using OpenMP with " & $omp_get_max_threads() & " threads]"
  else:
    "[Serial]"

template wrappedTest(desc: string, body: untyped): untyped =
  ## Wrap test in a proc to avoid having globals everywhere
  ## ballooning the test BSS space usage
  ## properly test destructors/GC/try-finally, ...
  ## aliasing
  ## and optimizations (that don't apply to globals)
  test desc:
    proc wTest() =
      body

    wTest()

proc keyGen(seed: uint64): tuple[pubkey: PublicKey, seckey: SecretKey] =
  var ikm: array[32, byte]
  ikm[0 ..< 8] = cast[array[8, byte]](seed)
  let ok = ikm.keyGen(result.pubkey, result.seckey)
  doAssert ok

proc hash[T: byte|char](message: openarray[T]): array[32, byte] {.noInit.}=
  result.bls_sha256_digest(message)

proc inclExample(batcher: var BatchedBLSVerifier, seed: int, message: string) =
  let (pubkey, seckey) = keyGen(seed.uint64)
  let hashed = hash(message)
  let sig = seckey.sign(hashed)
  doAssert batcher.incl(pubkey, hashed, sig)

# Test strategy
# As we use a tree algorithm we want to test
# - a single signature set
# - a signature set of size 2^n-1
# - a signature set of size 2^n
# - a signature set of size 2^n+1
# for boundary conditions
# we also want to test forged signature sets
# that would pass grouped verification
# https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407/16

let fakeRandomBytes = hash"Mr F was here"

suite "Batch verification " & omp_status():
  wrappedTest "Verify a single (pubkey, message, signature) triplet":
    let msg = hash"message"
    let (pubkey, seckey) = keyGen(123)
    let sig = seckey.sign(msg)

    var batcher = init(BatchedBLSVerifier[32])

    check:
      batcher.incl(pubkey, msg, sig)
      batcher.batchVerify(fakeRandomBytes)

  wrappedTest "Verify 2 (pubkey, message, signature) triplets":
    var batcher = init(BatchedBLSVerifier[32])
    batcher.inclExample(1, "msg1")
    batcher.inclExample(2, "msg2")

    check:
      batcher.batchVerify(fakeRandomBytes)

  wrappedTest "Verify 2^4 - 1 = 15 (pubkey, message, signature) triplets":
    var batcher = init(BatchedBLSVerifier[32])

    for i in 0 ..< 15:
      batcher.inclExample(i, "msg" & $i)

    check:
      batcher.batchVerify(fakeRandomBytes)

  wrappedTest "Verify 2^4 = 16 (pubkey, message, signature) triplets":
    var batcher = init(BatchedBLSVerifier[32])

    for i in 0 ..< 16:
      batcher.inclExample(i, "msg" & $i)

    check:
      batcher.batchVerify(fakeRandomBytes)

  wrappedTest "Verify 2^4 + 1 = 17 (pubkey, message, signature) triplets":
    var batcher = init(BatchedBLSVerifier[32])

    for i in 0 ..< 17:
      batcher.inclExample(i, "msg" & $i)

    check:
      batcher.batchVerify(fakeRandomBytes)

  wrappedTest "Wrong signature":
    let msg1 = hash"msg1"
    let msg2 = hash"msg2"
    let (pubkey1, seckey1) = keyGen(1)
    let sig1 = seckey1.sign(msg1)

    let (pubkey2, seckey2) = keyGen(2)

    var batcher = init(BatchedBLSVerifier[32])

    check:
      batcher.incl(pubkey1, msg1, sig1)
      batcher.incl(pubkey2, msg2, sig1) # <--- wrong signature
      not batcher.batchVerify(fakeRandomBytes)
