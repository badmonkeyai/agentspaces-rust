# Jackson text and wire vectors

Jackson's CBOR generator writes a text string longer than 3996 UTF-16 units as an
indefinite-length text (`0x7F`, definite text chunks, `0xFF`), and the Java codec now refuses a
definite text past that length (`WellFormedCbor` rule S6). This project records exactly what
`CborCodec.defaultCodec()` writes for long texts, so `agentspaces-wire` can prove its encoder and
decoder byte for byte against real Jackson rather than against a reading of its source.

`TextVectors` writes `crates/agentspaces-wire/tests/jackson-text-vectors.json`, which
`crates/agentspaces-wire/tests/jackson_text.rs` checks in both directions: the Rust encoding of
each case equals the Java hex, and the Rust decoding of the Java hex equals the case's value.

## The file

- `textChunk`: 3996, Jackson's `MAX_LONG_STRING_CHARS`.
- `codecAgreesWithPlainMapper`: whether `CborCodec.defaultCodec()` and a plain `CBORMapper` wrote
  the same bytes for every case (the codec's modules order maps and normalize numbers; they do not
  touch text).
- `emptyChunkSeen`: whether any chunk of any case was empty (Jackson never writes one).
- `mapKeysChunked`: whether a long `java.util.Map` key is chunked as a value is.
- `cases[]`, each with:
  - `name`, and `context`: `value` (the text alone), `field` (`record Field(String text)`),
    `bytesField` (`record WithBytes(String text, byte[] data)`, data `00 01 .. 3f`),
    `mapValue` (`Map.of("k", text)`), `mapKey` (`Map.of(text, "v")`), `arrayElement`
    (`record Items(List<String> items)` holding `["a", text, "z"]`), `nested`
    (`record Outer(String id, Field inner, int n)` holding `("o", Field(text), 7)`);
  - `text`: a recipe that rebuilds the text deterministically, a list of `[piece, count]` pairs
    concatenated in order (`piece` repeated `count` times);
  - `units` (UTF-16 length), `utf8` (UTF-8 length);
  - `chunks`: the UTF-16 length of each chunk Jackson wrote (empty when the text is definite);
  - `hex`: the bytes `CborCodec.defaultCodec().toBytes(value)` wrote, as lowercase hex.

## The wire vectors

`WireVectors` writes `crates/agentspaces-wire/tests/jackson-wire-vectors.json`, which
`crates/agentspaces-wire/tests/jackson_wire.rs` checks: the wire encoding that Java's
`WellFormedCbor` enforces (rules S1 to S12) on every document it reads from the network
(`CborCodec.fromWire`, `fromDocument`).

- `numbers[]`: a `BigInteger` or `BigDecimal` (`kind`, `text` as Java prints it, and for a
  decimal `normalized`, its `stripTrailingZeros()` text) in a `context` (`value` alone, `field`
  of `record Price(String item, BigDecimal amount, BigInteger serial)` with the other component
  1, `mapValue` of `Map.of("k", n)`, `arrayElement`: a list of two, bare for an integer and in
  `record Amounts(List<BigDecimal> amounts)` for a decimal), and the `hex` the codec wrote. Rust
  must write the same bytes and read them back to the same value.
- `documents[]`: an input `hex` (`name` says which rule it probes; the stamp items and
  the CBOR outside a stamp of SPEC §9 among them) with Java's two verdicts: `checkDocument`
  (the item rules alone) and `fromDocument` (the item rules, then Jackson, whose
  `StreamReadConstraints.maxNumberLength` refuses a bignum of more than 1000 bytes), each
  `accept` or the defect Java names. `cbor::decode` must accept exactly what `fromDocument`
  accepts.

The generator fails (exit 1) when a number's encoding does not read back through
`fromDocument`, so the vectors hold only what Java itself accepts.

## Regenerate

Maven runs offline against `~/.m2` (the AgentSpaces 0.5.0 jars and Jackson 2.21.7 must be there):

```sh
cd interop/jackson-vectors
mvn -q -o compile dependency:build-classpath -Dmdep.outputFile=target/classpath.txt
java -cp "target/classes:$(cat target/classpath.txt)" \
  ai.badmonkey.agentspaces.interop.vectors.TextVectors \
  ../../crates/agentspaces-wire/tests/jackson-text-vectors.json
java -cp "target/classes:$(cat target/classpath.txt)" \
  ai.badmonkey.agentspaces.interop.vectors.WireVectors \
  ../../crates/agentspaces-wire/tests/jackson-wire-vectors.json
```

The generator fails (exit 1) when a case's chunk boundaries break the rule it states, so a
Jackson upgrade that changes the boundaries shows up here before it shows up on the wire.
