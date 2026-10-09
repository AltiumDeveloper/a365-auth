package com.altium.auth;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class Json {
    private static final Pattern NUMBER = Pattern.compile("-?(?:0|[1-9]\\d*)(\\.\\d+)?([eE][+-]?\\d+)?");
    private static final int MAX_DEPTH = 64;

    private final String text;
    private int pos;
    private int depth;

    private Json(String text) {
        this.text = text;
    }

    static Object parse(String text) {
        Json parser = new Json(text);
        parser.skipWhitespace();
        Object value = parser.value();
        parser.skipWhitespace();
        if (parser.pos != text.length()) {
            throw parser.error("unexpected trailing characters");
        }
        return value;
    }

    static Object parseOrNull(String text) {
        try {
            return parse(text);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    private Object value() {
        if (pos >= text.length()) {
            throw error("unexpected end of input");
        }
        return switch (text.charAt(pos)) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> number();
        };
    }

    private Map<String, Object> object() {
        enter();
        Map<String, Object> map = new LinkedHashMap<>();
        pos++;
        skipWhitespace();
        if (consume('}')) {
            depth--;
            return map;
        }
        do {
            skipWhitespace();
            if (pos >= text.length() || text.charAt(pos) != '"') {
                throw error("expected an object key");
            }
            String key = string();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            map.put(key, value());
            skipWhitespace();
        } while (consume(','));
        expect('}');
        depth--;
        return map;
    }

    private List<Object> array() {
        enter();
        List<Object> list = new ArrayList<>();
        pos++;
        skipWhitespace();
        if (consume(']')) {
            depth--;
            return list;
        }
        do {
            skipWhitespace();
            list.add(value());
            skipWhitespace();
        } while (consume(','));
        expect(']');
        depth--;
        return list;
    }

    private String string() {
        pos++;
        StringBuilder out = new StringBuilder();
        while (pos < text.length()) {
            char c = text.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c < 0x20) {
                throw error("unescaped control character in string");
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (pos >= text.length()) {
                break;
            }
            char escaped = text.charAt(pos++);
            switch (escaped) {
                case '"', '\\', '/' -> out.append(escaped);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> out.append(unicodeEscape());
                default -> throw error("invalid escape \\" + escaped);
            }
        }
        throw error("unterminated string");
    }

    private char unicodeEscape() {
        if (pos + 4 > text.length()) {
            throw error("truncated \\u escape");
        }
        try {
            char c = (char) Integer.parseInt(text.substring(pos, pos + 4), 16);
            pos += 4;
            return c;
        } catch (NumberFormatException e) {
            throw error("invalid \\u escape");
        }
    }

    private Object number() {
        Matcher m = NUMBER.matcher(text).region(pos, text.length());
        if (!m.lookingAt()) {
            throw error("unexpected character '" + text.charAt(pos) + "'");
        }
        String token = m.group();
        pos = m.end();
        if (m.group(1) == null && m.group(2) == null) {
            try {
                return Long.parseLong(token);
            } catch (NumberFormatException overflow) {
                return Double.parseDouble(token);
            }
        }
        return Double.parseDouble(token);
    }

    private Object literal(String word, Object value) {
        if (!text.startsWith(word, pos)) {
            throw error("unexpected character '" + text.charAt(pos) + "'");
        }
        pos += word.length();
        return value;
    }

    private void enter() {
        if (++depth > MAX_DEPTH) {
            throw error("nesting deeper than " + MAX_DEPTH);
        }
    }

    private boolean consume(char c) {
        if (pos < text.length() && text.charAt(pos) == c) {
            pos++;
            return true;
        }
        return false;
    }

    private void expect(char c) {
        if (!consume(c)) {
            throw error("expected '" + c + "'");
        }
    }

    private void skipWhitespace() {
        while (pos < text.length() && " \t\r\n".indexOf(text.charAt(pos)) >= 0) {
            pos++;
        }
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("Malformed JSON at offset " + pos + ": " + message);
    }

    private static void write(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String s) {
            quote(s, out);
        } else if (value instanceof Boolean || value instanceof Number) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            String sep = "";
            for (Map.Entry<?, ?> e : map.entrySet()) {
                out.append(sep);
                quote(String.valueOf(e.getKey()), out);
                out.append(':');
                write(e.getValue(), out);
                sep = ",";
            }
            out.append('}');
        } else if (value instanceof Iterable<?> items) {
            out.append('[');
            String sep = "";
            for (Object item : items) {
                out.append(sep);
                write(item, out);
                sep = ",";
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("Cannot write " + value.getClass().getName() + " as JSON");
        }
    }

    private static void quote(String s, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
