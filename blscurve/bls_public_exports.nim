# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import bls_backend

export
  BLS_BACKEND, BlsBackendKind,
  SecretKey, PublicKey, Signature, ProofOfPossession,
  AggregateSignature, AggregatePublicKey,
  `==`,
  init, aggregate, finish, aggregateAll,
  publicFromSecret,
  fromHex, fromBytes, toHex, serialize, exportRaw

import bls_sig_min_pubkey

export
  sign,
  verify, aggregateVerify, fastAggregateVerify

when BLS_BACKEND == BLST:
  import ./blst/sha256_abi
  export sha256_abi
