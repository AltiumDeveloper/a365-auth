package com.altium.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

class JsonTest {
    @Test
    void parsesNestedValues() {
        Object parsed = Json.parse(" {\"a\": [1, -2.5e3, true, false, null], \"b\": {\"c\": \"d\"}, \"e\": {}} ");

        Map<String, Object> expected = new LinkedHashMap<>();
        expected.put("a", Arrays.asList(1L, -2500.0, true, false, null));
        expected.put("b", Map.of("c", "d"));
        expected.put("e", Map.of());
        assertEquals(expected, parsed);
    }

    @Test
    void decodesEscapes() {
        assertEquals("q\"b\\s/\b\f\n\r\t\u00e9\ud83d\ude00", Json.parse("\"q\\\"b\\\\s\\/\\b\\f\\n\\r\\t\\u00e9\\ud83d\\ude00\""));
    }

    @Test
    void returnsLargeIntegersAsDoubles() {
        assertEquals(1e20, Json.parse("100000000000000000000"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not json", "{\"a\":1,}", "[1,]", "{\"a\" 1}", "\"unterminated", "01", "[1] x", "{'a':1}",
            "\"\\x\"", "\"\\u12\"", "tru", "\"a\nb\""})
    void rejectsMalformedInput(String input) {
        assertThrows(IllegalArgumentException.class, () -> Json.parse(input));
    }

    @Test
    void rejectsExcessiveNesting() {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(100) + "]".repeat(100)));
    }

    @Test
    void parseOrNullSwallowsMalformedInput() {
        assertNull(Json.parseOrNull("<html>"));
    }

    @Test
    void writeRoundTrips() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("s", "a\"b\\c\n\u0001");
        value.put("n", 3600L);
        value.put("l", List.of(true, "x"));
        value.put("z", null);

        String written = Json.write(value);

        assertEquals("{\"s\":\"a\\\"b\\\\c\\n\\u0001\",\"n\":3600,\"l\":[true,\"x\"],\"z\":null}", written);
        assertEquals(value, Json.parse(written));
    }
}
