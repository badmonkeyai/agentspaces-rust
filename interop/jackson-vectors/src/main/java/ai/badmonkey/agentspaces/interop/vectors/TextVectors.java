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
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Writes what {@code CborCodec.defaultCodec()} encodes for texts around Jackson's chunk length
 * (3996 UTF-16 units), in every context a text takes on the wire, as JSON test vectors for
 * agentspaces-rust. See README.md for the file's shape.
 *
 * <p>Argument: the output path. Exit 1 when a case breaks the chunking rule the vectors document
 * (only a text past 3996 units is chunked; while more than 3996 remain the next chunk takes 3996
 * units, or 3995 when its last unit would be a high surrogate; the rest forms the last chunk).
 */
public final class TextVectors {

    /** Jackson's {@code MAX_LONG_STRING_CHARS}. */
    static final int TEXT_CHUNK = 3996;

    /** A record with one text field. */
    public record Field(String text) {
    }

    /** A record whose text sits beside a byte string. */
    public record WithBytes(String text, byte[] data) {
    }

    /** A record whose one field is a list of texts. */
    public record Items(List<String> items) {
    }

    /** A record nesting a {@link Field} between two other components. */
    public record Outer(String id, Field inner, int n) {
    }

    /** One piece of a text recipe: {@code piece} repeated {@code count} times. */
    record Piece(String piece, int count) {
    }

    /** A named text, built from its recipe. */
    record Text(String name, List<Piece> recipe) {
        String build() {
            StringBuilder out = new StringBuilder();
            for (Piece p : recipe) {
                out.append(p.piece().repeat(p.count()));
            }
            return out.toString();
        }
    }

    private static final String SMILE = "😀"; // U+1F600, 4 bytes in UTF-8, 2 UTF-16 units
    private static final String CLEF = "𝄞";  // U+1D11E

    private static final byte[] DATA = new byte[64];

    static {
        for (int i = 0; i < DATA.length; i++) {
            DATA[i] = (byte) i;
        }
    }

    private TextVectors() {
    }

    private static Piece p(String piece, int count) {
        return new Piece(piece, count);
    }

    private static Text t(String name, Piece... pieces) {
        return new Text(name, List.of(pieces));
    }

    /** Every case, in the field context; {@link #EVERY_CONTEXT} names those also in the others. */
    static List<Text> texts() {
        List<Text> texts = new ArrayList<>();
        for (int n : new int[]{0, 1, 23, 24, 255, 256, 3995, 3996, 3997, 7991, 7992, 7993, 7994, 11988, 11989, 12000}) {
            texts.add(t("ascii-" + n, p("a", n)));
        }
        // Two-byte UTF-8 (U+00E9) and three-byte UTF-8 (U+4E2D, U+20AC): one UTF-16 unit each.
        texts.add(t("latin1-3996", p("é", 3996)));
        texts.add(t("latin1-3997", p("é", 3997)));
        texts.add(t("latin1-8000", p("é", 8000)));
        texts.add(t("ascii-3995-latin1-2", p("a", 3995), p("é", 2)));
        texts.add(t("cjk-3996", p("中", 3996)));
        texts.add(t("cjk-3997", p("中", 3997)));
        texts.add(t("cjk-9000", p("中", 9000)));
        texts.add(t("ascii-3994-euro-5", p("a", 3994), p("€", 5)));
        // A surrogate pair whose high surrogate sits at unit k (0-based): k = 3995 is the last unit
        // of the first chunk, so that chunk takes 3995 units.
        texts.add(t("pair-ends-at-3996", p("a", 3994), p(SMILE, 1)));
        texts.add(t("pair-ends-at-3997", p("a", 3995), p(SMILE, 1)));
        for (int k : new int[]{3993, 3994, 3995, 3996, 3997}) {
            texts.add(t("pair-high-at-" + k, p("a", k), p(SMILE, 1), p("a", 4100 - k - 2)));
        }
        // The second chunk boundary: unit 7991 after a full first chunk, unit 7990 after a 3995 one.
        texts.add(t("pair-high-at-7991", p("a", 7991), p(SMILE, 1), p("a", 200)));
        texts.add(t("pair-high-at-3995-and-7990", p("a", 3995), p(SMILE, 1), p("a", 3993), p(SMILE, 1),
                p("a", 200)));
        // Every boundary shifted: high surrogates at 3995, 7990, and 11985.
        texts.add(t("pair-high-at-3995-7990-11985", p("a", 3995), p(SMILE, 1), p("a", 3993), p(SMILE, 1),
                p("a", 3993), p(CLEF, 1), p("a", 100)));
        // All surrogate pairs: aligned (high surrogates at even units) and shifted by one unit.
        texts.add(t("pairs-2000", p(SMILE, 2000)));
        texts.add(t("pairs-6000", p(SMILE, 6000)));
        texts.add(t("a-then-pairs-2500", p("a", 1), p(SMILE, 2500)));
        texts.add(t("a-then-pairs-6000", p("a", 1), p(CLEF, 6000)));
        // Every UTF-8 width in a five-unit pattern: aligned, and shifted so every boundary splits.
        texts.add(t("mixed-2000", p("aé中" + SMILE, 2000)));
        texts.add(t("xy-mixed-2000", p("xy", 1), p("aé中" + SMILE, 2000)));
        return texts;
    }

    /** The cases also written in every other context. */
    static final List<String> EVERY_CONTEXT = List.of("ascii-1", "ascii-3996", "ascii-3997", "ascii-7993",
            "pair-high-at-3995", "pairs-2000", "xy-mixed-2000");

    /** The value a context wraps a text in. */
    static Object wrap(String context, String text) {
        return switch (context) {
            case "value" -> text;
            case "field" -> new Field(text);
            case "bytesField" -> new WithBytes(text, DATA);
            case "mapValue" -> Map.of("k", text);
            case "mapKey" -> Map.of(text, "v");
            case "arrayElement" -> new Items(List.of("a", text, "z"));
            case "nested" -> new Outer("o", new Field(text), 7);
            default -> throw new IllegalArgumentException(context);
        };
    }

    public static void main(String[] args) throws IOException {
        Path out = Path.of(args[0]);
        CborCodec codec = CborCodec.defaultCodec();
        CBORMapper plain = new CBORMapper();
        HexFormat hex = HexFormat.of();
        boolean agree = true;
        boolean emptyChunk = false;
        boolean keysChunked = false;
        boolean ruleHolds = true;
        StringBuilder cases = new StringBuilder();
        int count = 0;
        for (Text text : texts()) {
            String value = text.build();
            List<Integer> chunks = chunks(codec.toBytes(value));
            emptyChunk |= chunks.contains(0);
            List<Integer> expected = expectedChunks(value);
            if (!chunks.equals(expected)) {
                System.err.println(text.name() + ": Jackson chunked " + chunks + ", the rule says " + expected);
                ruleHolds = false;
            }
            List<String> contexts = new ArrayList<>(List.of("field"));
            if (EVERY_CONTEXT.contains(text.name())) {
                contexts = List.of("value", "field", "bytesField", "mapValue", "mapKey", "arrayElement", "nested");
            }
            for (String context : contexts) {
                Object wrapped = wrap(context, value);
                byte[] written = codec.toBytes(wrapped);
                byte[] plainWritten = plain.writeValueAsBytes(wrapped);
                if (!java.util.Arrays.equals(written, plainWritten)) {
                    System.err.println(text.name() + "/" + context + ": the codec and a plain CBORMapper differ");
                    agree = false;
                }
                if (context.equals("mapKey") && value.length() > TEXT_CHUNK && (written[1] & 0xFF) == 0x7F) {
                    keysChunked = true;
                }
                if (count > 0) {
                    cases.append(",\n");
                }
                cases.append("    {\"name\": ").append(json(text.name()))
                        .append(", \"context\": ").append(json(context))
                        .append(", \"text\": [");
                for (int i = 0; i < text.recipe().size(); i++) {
                    Piece piece = text.recipe().get(i);
                    cases.append(i == 0 ? "" : ", ").append('[').append(json(piece.piece())).append(", ")
                            .append(piece.count()).append(']');
                }
                cases.append("], \"units\": ").append(value.length())
                        .append(", \"utf8\": ").append(value.getBytes(StandardCharsets.UTF_8).length)
                        .append(", \"chunks\": ").append(chunks)
                        .append(", \"hex\": \"").append(hex.formatHex(written)).append("\"}");
                count++;
            }
        }
        String document = "{\n"
                + "  \"generator\": \"interop/jackson-vectors TextVectors (CborCodec.defaultCodec(), agentspaces-common "
                + "0.5.0, jackson-dataformat-cbor " + com.fasterxml.jackson.dataformat.cbor.PackageVersion.VERSION + ")\",\n"
                + "  \"textChunk\": " + TEXT_CHUNK + ",\n"
                + "  \"codecAgreesWithPlainMapper\": " + agree + ",\n"
                + "  \"emptyChunkSeen\": " + emptyChunk + ",\n"
                + "  \"mapKeysChunked\": " + keysChunked + ",\n"
                + "  \"cases\": [\n" + cases + "\n  ]\n}\n";
        Files.writeString(out, document, StandardCharsets.US_ASCII);
        System.out.println("{\"cases\":" + count + ",\"codecAgreesWithPlainMapper\":" + agree
                + ",\"emptyChunkSeen\":" + emptyChunk + ",\"mapKeysChunked\":" + keysChunked
                + ",\"ruleHolds\":" + ruleHolds + "}");
        if (!ruleHolds) {
            System.exit(1);
        }
    }

    /** The UTF-16 length of each chunk of the text item {@code bytes} holds; empty when definite. */
    static List<Integer> chunks(byte[] bytes) {
        List<Integer> lengths = new ArrayList<>();
        if ((bytes[0] & 0xFF) != 0x7F) {
            return lengths;
        }
        int at = 1;
        while ((bytes[at] & 0xFF) != 0xFF) {
            int head = bytes[at] & 0xFF;
            if (head >>> 5 != 3) {
                throw new IllegalStateException("a chunk of major type " + (head >>> 5));
            }
            int info = head & 0x1F;
            int width = info < 24 ? 0 : 1 << (info - 24);
            long length = info < 24 ? info : 0;
            for (int i = 1; i <= width; i++) {
                length = (length << 8) | (bytes[at + i] & 0xFF);
            }
            int from = at + 1 + width;
            lengths.add(new String(bytes, from, (int) length, StandardCharsets.UTF_8).length());
            at = from + (int) length;
        }
        return lengths;
    }

    /** The chunk lengths the documented rule gives (WellFormedCbor S6). */
    static List<Integer> expectedChunks(String text) {
        List<Integer> lengths = new ArrayList<>();
        int remaining = text.length();
        if (remaining <= TEXT_CHUNK) {
            return lengths;
        }
        int offset = 0;
        while (remaining > TEXT_CHUNK) {
            int take = Character.isHighSurrogate(text.charAt(offset + TEXT_CHUNK - 1)) ? TEXT_CHUNK - 1 : TEXT_CHUNK;
            lengths.add(take);
            offset += take;
            remaining -= take;
        }
        lengths.add(remaining);
        return lengths;
    }

    /** A JSON string, every character outside printable ASCII as a backslash-u escape. */
    static String json(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20 || c > 0x7E) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.append('"').toString();
    }
}
