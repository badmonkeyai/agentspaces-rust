/*
 * Copyright 2026 Bad Monkey, Inc.
 * Author: Al Baker
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.badmonkey.agentspaces.interop.vectors;

import ai.badmonkey.agentspaces.common.codec.CborCodec;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes the wire encoding ({@code WellFormedCbor} rules S1 to S12) as JSON test vectors for
 * agentspaces-rust, from the installed Java codec:
 *
 * <ul>
 *   <li>{@code numbers}: what {@code CborCodec.defaultCodec()} writes for a {@code BigInteger}
 *       or a {@code BigDecimal}, alone and in a record, a map, and a list;</li>
 *   <li>{@code documents}: an input and what Java makes of it, {@code CborCodec.checkDocument}
 *       (the item rules alone) and {@code fromDocument(bytes, Object.class)} (the item rules, then
 *       Jackson, whose number-length constraint refuses a bignum of more than 1000 bytes), each
 *       {@code accept} or the defect Java names.</li>
 * </ul>
 *
 * <p>Argument: the output path. Exit 1 when a number's encoding does not read back through
 * {@code fromDocument} to its value, so the vectors only hold what Java itself accepts.
 */
public final class WireVectors {

    private static final HexFormat HEX = HexFormat.of();

    /** A record holding both big-number kinds beside text. */
    public record Price(String item, BigDecimal amount, BigInteger serial) {
    }

    /** A record holding a list. */
    public record Amounts(List<BigDecimal> amounts) {
    }

    private WireVectors() {
    }

    /** The big integers: around the long range, around 64 bits, and the longest Jackson reads. */
    static List<BigInteger> integers() {
        BigInteger two63 = BigInteger.ONE.shiftLeft(63);
        BigInteger two64 = BigInteger.ONE.shiftLeft(64);
        byte[] longest = new byte[1000];
        longest[0] = 0x7F;
        for (int i = 1; i < longest.length; i++) {
            longest[i] = (byte) 0xFF;
        }
        return List.of(
                BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(-1),
                BigInteger.valueOf(Long.MAX_VALUE), BigInteger.valueOf(Long.MIN_VALUE),
                two63, two63.negate().subtract(BigInteger.ONE), two63.add(BigInteger.ONE),
                two64.subtract(BigInteger.ONE), two64, two64.negate(), two64.negate().subtract(BigInteger.ONE),
                two64.add(BigInteger.ONE), BigInteger.ONE.shiftLeft(70), BigInteger.ONE.shiftLeft(70).negate(),
                BigInteger.TEN.pow(30), BigInteger.TEN.pow(40).negate(), BigInteger.ONE.shiftLeft(127),
                BigInteger.ONE.shiftLeft(128), new BigInteger(longest), new BigInteger(longest).negate());
    }

    /** The decimals: plain and scientific, normalized by the codec, and at the exponent's ends. */
    static List<BigDecimal> decimals() {
        return List.of(
                new BigDecimal("1.25"), new BigDecimal("-12.5"), new BigDecimal("0"), new BigDecimal("0.00"),
                new BigDecimal("1.50"), new BigDecimal("1000"), new BigDecimal("1E+3"), new BigDecimal("0.001"),
                new BigDecimal("0.0000125"), new BigDecimal("1.25E-7"), new BigDecimal("-0.5"),
                new BigDecimal(BigInteger.ONE.shiftLeft(31), 3), new BigDecimal(BigInteger.ONE.shiftLeft(70), 5),
                new BigDecimal(BigInteger.ONE.shiftLeft(64).negate(), 2), new BigDecimal("1E+2147483647"),
                new BigDecimal("1E-2147483647"), new BigDecimal("123456789012345678901234567890.123456789"),
                new BigDecimal("9223372036854775807"), new BigDecimal("9223372036854775808"),
                new BigDecimal("-9223372036854775809"), new BigDecimal("3.14159265358979323846264338327950288"));
    }

    /** One input document, by name and hex, whose verdicts Java gives. */
    record Doc(String name, String hex) {
    }

    private static String repeat(String hex, int times) {
        return hex.repeat(times);
    }

    private static String text(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        return head(3, b.length) + HEX.formatHex(b);
    }

    private static String head(int major, long n) {
        int m = major << 5;
        if (n < 24) {
            return HEX.formatHex(new byte[]{(byte) (m | n)});
        } else if (n < 0x100) {
            return HEX.formatHex(new byte[]{(byte) (m | 24), (byte) n});
        } else if (n < 0x10000) {
            return HEX.formatHex(new byte[]{(byte) (m | 25), (byte) (n >> 8), (byte) n});
        }
        return HEX.formatHex(new byte[]{(byte) (m | 26), (byte) (n >> 24), (byte) (n >> 16), (byte) (n >> 8),
                (byte) n});
    }

    private static String bignum(int tag, int length) {
        StringBuilder out = new StringBuilder(tag == 2 ? "c2" : "c3").append(head(2, length)).append("7f");
        out.append("ff".repeat(length - 1));
        return out.toString();
    }

    /** The inputs: every rule, both sides of each boundary. */
    static List<Doc> documents() {
        List<Doc> docs = new ArrayList<>();
        // The stamp item (SPEC §9): a stamp alone, in 26 encodings named stamp row 1 to 26.
        String row2 = "1762560000000:65536:zPeer";
        String[] rows = {
            "65353a303a6e", "78" + "19" + HEX.formatHex(row2.getBytes(StandardCharsets.UTF_8)), "66353a303ac3b1",
            "68353a303af09f9880", "7805353a303a6e", "790005353a303a6e", "7a00000005353a303a6e",
            "7b0000000000000005353a303a6e", "790019" + HEX.formatHex(row2.getBytes(StandardCharsets.UTF_8)),
            "7f65353a303a6eff", "7f62353a63303a6eff", "c065353a303a6e", "d82065353a303a6e",
            "d9d9f765353a303a6e", "66353a303ac1ae", "67353a303ae081ae", "6635c0ba303a6e", "67353a303aeda080",
            "65353a303aff", "66353a303a6e80", "45353a303a6e", "05", "fb4014000000000000", "a0",
            "8165353a303a6e", "f6"};
        for (int i = 0; i < rows.length; i++) {
            docs.add(new Doc("stamp row " + (i + 1), rows[i]));
        }
        // CBOR outside a stamp (SPEC §9): text chunks, tags, bignums, decimals, tagged keys, and
        // malformed UTF-8, as the rules S1 to S12 judge them.
        for (String h : new String[]{"7f636162636364656 6ff".replace(" ", ""), "c24180", "c249010000000000000000",
                "c341ff", "c48221187d", "c4823a7fffffff01", "c4821a8000000001", "c06161", "c11a5f000000", "d82a4100",
                "d9d9f701", "c2c24101", "c201", "c25f4101ff", "c4832001 01".replace(" ", ""), "c48200f93c00",
                "c482006131", "c49f2001ff", "a1c241016178", "a1c48200016178", "a1c0616161 78".replace(" ", ""),
                "62c1a5", "63eda080", "7f416161ff"}) {
            docs.add(new Doc("section 14.8 " + h, h));
        }
        // S1: one item, nothing after it.
        docs.add(new Doc("S1 trailing byte", "0000"));
        docs.add(new Doc("S1 empty", ""));
        // S2: 64 levels, the decimal's array counted as one.
        docs.add(new Doc("S2 64 arrays", repeat("81", 64) + "00"));
        docs.add(new Doc("S2 65 arrays", repeat("81", 65) + "00"));
        docs.add(new Doc("S2 decimal at level 64", repeat("81", 63) + "c4820001"));
        docs.add(new Doc("S2 decimal at level 65", repeat("81", 64) + "c4820001"));
        docs.add(new Doc("S2 64 maps", repeat("bf6161", 64) + "00" + repeat("ff", 64)));
        docs.add(new Doc("S2 65 maps", repeat("bf6161", 65) + "00" + repeat("ff", 65)));
        // S3: the shortest head.
        for (String h : new String[]{"17", "1817", "1818", "1900ff", "190100", "1a0000ffff", "1a00010000",
                "1b00000000ffffffff", "1b0000000100000000", "3817", "5800", "4100", "9800", "8100",
                "d80249010000000000000000", "c25809010000000000000000", "c2490100000000000000 00".replace(" ", "")}) {
            docs.add(new Doc("S3 " + h, h));
        }
        docs.add(new Doc("S3 a chunk under a wide head", "7f790f9c" + "61".repeat(3996) + "780161ff"));
        // S4: a plain integer inside a long.
        for (String h : new String[]{"1b7fffffffffffffff", "1b8000000000000000", "1bffffffffffffffff",
                "3b7fffffffffffffff", "3b8000000000000000", "3bffffffffffffffff"}) {
            docs.add(new Doc("S4 " + h, h));
        }
        // S5: definite byte strings.
        docs.add(new Doc("S5 indefinite bytes", "5f4100ff"));
        docs.add(new Doc("S5 empty indefinite bytes", "5fff"));
        // S6: text chunked exactly as Jackson chunks it.
        String a3995 = "61".repeat(3995);
        String a3996 = "61".repeat(3996);
        String smile = "f09f9880";
        docs.add(new Doc("S6 empty chunked", "7fff"));
        docs.add(new Doc("S6 chunked short", "7f6161ff"));
        docs.add(new Doc("S6 chunked short with empty chunks", "7f6060ff"));
        docs.add(new Doc("S6 reviewer short chunks", "7f6161606162ff"));
        docs.add(new Doc("S6 definite 3996", "790f9c" + a3996));
        docs.add(new Doc("S6 definite 3997", "790f9d" + a3996 + "61"));
        docs.add(new Doc("S6 jackson 3997", "7f790f9c" + a3996 + "6161ff"));
        docs.add(new Doc("S6 3997 split 3995 + 2", "7f790f9b" + a3995 + "626161ff"));
        docs.add(new Doc("S6 3997 with an empty chunk", "7f790f9c" + a3996 + "616160ff"));
        docs.add(new Doc("S6 3997 one chunk", "7f790f9d" + a3996 + "61ff"));
        docs.add(new Doc("S6 3996 one chunk", "7f790f9c" + a3996 + "ff"));
        docs.add(new Doc("S6 reviewer 5000 definite", "791388" + "61".repeat(5000)));
        docs.add(new Doc("S6 reviewer 2500 + 2500", "7f7909c4" + "61".repeat(2500) + "7909c4" + "61".repeat(2500)
                + "ff"));
        docs.add(new Doc("S6 pair after 3995", "7f790f9b" + a3995 + "65" + smile + "62ff"));
        docs.add(new Doc("S6 pair after 3994 in the first chunk", "7f790f9e" + "61".repeat(3994) + smile
                + "6a" + "62".repeat(10) + "ff"));
        docs.add(new Doc("S6 pair after 3994 split early", "7f790f9a" + "61".repeat(3994) + "6e" + smile
                + "62".repeat(10) + "ff"));
        docs.add(new Doc("S6 long key", "bf7f790f9c" + a3996 + "6161ff01ff"));
        docs.add(new Doc("S6 short chunked key", "bf7f6161ff01ff"));
        // S7: definite arrays.
        docs.add(new Doc("S7 indefinite array", "9f01ff"));
        docs.add(new Doc("S7 empty indefinite array", "9fff"));
        // S8: indefinite maps of distinct text keys.
        for (String h : new String[]{"a0", "a1616101", "bfff", "bf616101616201ff", "bf616101616102ff", "bf0101ff",
                "bf2001ff", "bf410101ff", "bf810101ff", "bfbfff01ff", "bff601ff", "bff401ff", "bffb3ff000000000000001ff",
                "bf7f6161ff01616101ff"}) {
            docs.add(new Doc("S8 " + h, h));
        }
        // S9: bignums and decimals in their one form; no other tag; never a key.
        for (String h : new String[]{"c249008000000000000000", "c2487fffffffffffffff", "c240", "c24100",
                "c2420080", "c243000080", "c349008000000000000000", "c349008000000000000001", "c3487fffffffffffffff",
                "c24900ffffffffffffffff", "c349010000000000000000", "c249010000000000000000",
                "c34a01000000000000000000", "c4820000", "c4820100", "c482000a", "c4820029", "c4822115", "c4822139",
                "c4823a7ffffffe01", "c4821a7fffffff01", "c4821b000000010000000001", "c4823b000000007fffffff01",
                "c48200c249010000000000000000", "c48200c24101", "c48220c349010000000000000001",
                "c48201c2490a0000000000000000", "c482c2410101", "c4820001",
                "c48100", "c4a0", "c4f6", "c5820001", "d81e820001", "c3c24101", "bfc24101 6178ff".replace(" ", ""),
                "bfc4820001 6178ff".replace(" ", ""), "bfc0616161 78ff".replace(" ", ""), "dfff"}) {
            docs.add(new Doc("S9 " + h, h));
        }
        docs.add(new Doc("S9 bignum of 1000 bytes", bignum(2, 1000)));
        docs.add(new Doc("S9 bignum of 1001 bytes", bignum(2, 1001)));
        docs.add(new Doc("S9 negative bignum of 1000 bytes", bignum(3, 1000)));
        docs.add(new Doc("S9 negative bignum of 1001 bytes", bignum(3, 1001)));
        docs.add(new Doc("S9 decimal mantissa of 1000 bytes", "c48221" + bignum(2, 1000)));
        docs.add(new Doc("S9 decimal mantissa of 1001 bytes", "c48221" + bignum(2, 1001)));
        // S10: float32 and float64 with one NaN each, no half.
        for (String h : new String[]{"f93c00", "f97e00", "fa3fc00000", "fa7fc00000", "fa7fc00001", "faffc00000",
                "fa7f800000", "fb7ff8000000000000", "fbfff8000000000000", "fb7ff8000000000001", "fb7ff0000000000000",
                "fb8000000000000000"}) {
            docs.add(new Doc("S10 " + h, h));
        }
        // S11: false, true, null.
        for (String h : new String[]{"f4", "f5", "f6", "f7", "f0", "e0", "f818", "f820", "fc", "fd", "fe"}) {
            docs.add(new Doc("S11 " + h, h));
        }
        // S12: a break only where it ends an indefinite map or text.
        for (String h : new String[]{"ff", "8101ff", "bf6161ffff", "bf6161ff", "8201ff"}) {
            docs.add(new Doc("S12 " + h, h));
        }
        // Well-formed UTF-8 everywhere, in a chunk as well.
        docs.add(new Doc("UTF-8 split across chunks", "7f790f9c" + a3995 + "c3" + "62a962ff"));
        docs.add(new Doc("UTF-8 surrogate in a long text", "790f9d" + "61".repeat(3994) + "eda080"));
        // Honest documents.
        docs.add(new Doc("a record", "bf646974656d617866616d6f756e74c48221187d6673657269616cc24900ffffffffffffffffff"));
        docs.add(new Doc("a map with a long text", "bf616b7f790f9c" + a3996 + "6161ffff"));
        return docs;
    }

    private static String checkDocument(byte[] bytes) {
        try {
            CborCodec.checkDocument(bytes);
            return "accept";
        } catch (UncheckedIOException e) {
            return e.getCause() == null ? e.getMessage() : e.getCause().getMessage();
        }
    }

    private static String fromDocument(byte[] bytes) {
        try {
            CborCodec.defaultCodec().fromDocument(bytes, Object.class);
            return "accept";
        } catch (RuntimeException e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            return String.valueOf(cause.getMessage()).lines().findFirst().orElse("refused");
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("usage: WireVectors OUTPUT.json");
            System.exit(2);
        }
        CborCodec codec = CborCodec.defaultCodec();
        StringBuilder out = new StringBuilder("{\n  \"numbers\": [\n");
        List<String> rows = new ArrayList<>();
        boolean ok = true;
        for (BigInteger n : integers()) {
            Map<String, Object> contexts = new LinkedHashMap<>();
            contexts.put("value", n);
            contexts.put("field", new Price("p", BigDecimal.ONE, n));
            contexts.put("mapValue", Map.of("k", n));
            contexts.put("arrayElement", List.of(n, n));
            for (Map.Entry<String, Object> c : contexts.entrySet()) {
                byte[] bytes = codec.toBytes(c.getValue());
                ok &= reads(bytes);
                rows.add("    {\"kind\": \"integer\", \"text\": \"" + n + "\", \"context\": \"" + c.getKey()
                        + "\", \"hex\": \"" + HEX.formatHex(bytes) + "\"}");
            }
        }
        for (BigDecimal d : decimals()) {
            Map<String, Object> contexts = new LinkedHashMap<>();
            contexts.put("value", d);
            contexts.put("field", new Price("p", d, BigInteger.ONE));
            contexts.put("mapValue", Map.of("k", d));
            contexts.put("arrayElement", new Amounts(List.of(d, d)));
            for (Map.Entry<String, Object> c : contexts.entrySet()) {
                byte[] bytes = codec.toBytes(c.getValue());
                ok &= reads(bytes);
                BigDecimal stripped = d.signum() == 0 ? BigDecimal.ZERO : d.stripTrailingZeros();
                rows.add("    {\"kind\": \"decimal\", \"text\": \"" + d + "\", \"normalized\": \"" + stripped
                        + "\", \"context\": \"" + c.getKey() + "\", \"hex\": \"" + HEX.formatHex(bytes) + "\"}");
            }
        }
        out.append(String.join(",\n", rows)).append("\n  ],\n  \"documents\": [\n");
        rows.clear();
        for (Doc doc : documents()) {
            byte[] bytes = HEX.parseHex(doc.hex());
            rows.add("    {\"name\": " + json(doc.name()) + ", \"hex\": \"" + doc.hex() + "\", \"checkDocument\": "
                    + json(checkDocument(bytes)) + ", \"fromDocument\": " + json(fromDocument(bytes)) + "}");
        }
        out.append(String.join(",\n", rows)).append("\n  ]\n}\n");
        Files.writeString(Path.of(args[0]), out.toString());
        if (!ok) {
            System.err.println("a number's encoding does not read back through fromDocument");
            System.exit(1);
        }
    }

    private static boolean reads(byte[] bytes) {
        try {
            CborCodec.defaultCodec().fromDocument(bytes, Object.class);
            CborCodec.checkDocument(bytes);
            return true;
        } catch (RuntimeException e) {
            System.err.println(HEX.formatHex(bytes) + ": " + e);
            return false;
        }
    }

    private static String json(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                default -> {
                    if (c < 0x20 || c > 0x7E) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }
}
