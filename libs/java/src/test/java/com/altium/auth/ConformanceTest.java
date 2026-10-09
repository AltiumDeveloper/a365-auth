package com.altium.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

class ConformanceTest {
    private static final Map<String, Object> VECTORS = loadVectors();

    @TestFactory
    Stream<DynamicTest> authorizeUrl() {
        return vectors("authorizeUrl").map(v -> dynamicTest(id(v), () -> {
            AltiumAuthClient client = new AltiumAuthClient(config(map(v.get("config"))), unusedHttp());
            Map<String, Object> options = map(v.get("options"));
            WorkspaceSelection selection = options.containsKey("selectWorkspace")
                    ? WorkspaceSelection.valueOf(str(options.get("selectWorkspace")).toUpperCase(Locale.ROOT))
                    : WorkspaceSelection.NONE;

            AuthorizationRequest request = client.createAuthorizationUrl(
                    str(options.get("redirectUri")), str(options.get("state")), str(options.get("codeVerifier")), selection);

            URI url = URI.create(request.url());
            Map<String, String> query = parseForm(url.getRawQuery());
            Map<String, Object> expect = map(v.get("expect"));
            assertEquals(expect.get("origin"), url.getScheme() + "://" + url.getRawAuthority());
            assertEquals(expect.get("pathname"), url.getPath());
            map(expect.getOrDefault("query", Map.of())).forEach((key, matcher) ->
                    assertTrue(matches(query.get(key), matcher), "query " + key + "=" + query.get(key)));
            strings(expect.getOrDefault("queryAbsent", List.of())).forEach(key ->
                    assertFalse(query.containsKey(key), "query " + key + " should be absent"));
        }));
    }

    @TestFactory
    Stream<DynamicTest> tokenRequest() {
        return vectors("tokenRequest").map(v -> dynamicTest(id(v), () -> {
            AltiumAuthConfig config = config(map(v.get("config")));
            FakeHttpClient http = replying(map(v.get("mockResponse")));
            AltiumAuthClient client = new AltiumAuthClient(config, http);
            Map<String, Object> input = map(v.get("input"));
            Supplier<TokenSet> run = switch (str(v.get("operation"))) {
                case "exchangeCode" -> () -> client.exchangeCode(
                        str(input.get("code")), str(input.get("codeVerifier")), str(input.get("redirectUri")));
                case "signIntoWorkspace" -> () -> client.signIntoWorkspace(
                        str(input.get("baseAccessToken")), str(input.get("workspaceAuthId")));
                case "refreshToken" -> () -> client.refreshToken(str(input.get("refreshToken")));
                default -> throw new AssertionError("unknown operation " + v.get("operation"));
            };

            if (v.containsKey("expectErrorContains")) {
                AltiumAuthException error = assertThrows(AltiumAuthException.class, run::get);
                assertTrue(error.getMessage().contains(str(v.get("expectErrorContains"))), error.getMessage());
            } else {
                TokenSet tokens = run.get();
                map(v.getOrDefault("expectResult", Map.of())).forEach((key, expected) ->
                        assertResultField(tokenField(tokens, key), expected, key));
            }
            assertFalse(http.calls.isEmpty());
            checkRequest(http.calls.get(0), map(v.getOrDefault("expectRequest", Map.of())), config);
        }));
    }

    @TestFactory
    Stream<DynamicTest> revocation() {
        return vectors("revocation").filter(v -> v.containsKey("expectRequest")).map(v -> dynamicTest(id(v), () -> {
            AltiumAuthConfig config = config(map(v.get("config")));
            FakeHttpClient http = replying(map(v.get("mockResponse")));

            new AltiumAuthClient(config, http).revokeRefreshToken(str(map(v.get("input")).get("refreshToken")));

            assertFalse(http.calls.isEmpty());
            checkRequest(http.calls.get(0), map(v.get("expectRequest")), config);
        }));
    }

    @TestFactory
    Stream<DynamicTest> actionWait() {
        return vectors("actionWait").map(v -> dynamicTest(id(v), () -> {
            List<Object> polls = list(v.get("pollResponses"));
            AtomicInteger pollCount = new AtomicInteger();
            FakeHttpClient http = new FakeHttpClient(call -> {
                if (!call.url().contains("actionwait")) {
                    return new FakeHttpClient.Reply(200, "{\"access_token\":\"AT\",\"token_type\":\"Bearer\"}");
                }
                FakeHttpClient.Reply reply = mockReply(map(polls.get(Math.min(pollCount.getAndIncrement(), polls.size() - 1))));
                String waitToken = str(map(Json.parse(call.body())).get("token"));
                return new FakeHttpClient.Reply(reply.status(), reply.body().replace("<stateEchoesToken>", waitToken));
            });
            AltiumAuthClient client = new AltiumAuthClient(
                    AltiumAuthConfig.builder("c", "openid profile").openBrowser(url -> { }).build(), http);
            Map<String, Object> expect = map(v.get("expect"));

            if ("code".equals(expect.get("outcome"))) {
                assertEquals("AT", client.signIn(WorkspaceSelection.NONE, Duration.ofSeconds(2)).accessToken());
            } else {
                AltiumAuthException error = assertThrows(AltiumAuthException.class,
                        () -> client.signIn(WorkspaceSelection.NONE, Duration.ofSeconds(2)));
                assertTrue(error.getMessage().contains(str(expect.get("errorContains"))), error.getMessage());
            }
        }));
    }

    @TestFactory
    Stream<DynamicTest> clientScopes() {
        return vectors("clientScopes").map(v -> dynamicTest(id(v), () -> {
            FakeHttpClient http = replying(map(v.get("mockResponse")));
            Map<String, Object> input = map(v.get("input"));
            Supplier<List<String>> run = () -> AltiumAuthClient.getClientScopes(
                    http, str(input.get("scopeEndpoint")), str(input.get("clientId")));

            if (v.containsKey("expectErrorContains")) {
                AltiumAuthException error = assertThrows(AltiumAuthException.class, run::get);
                assertTrue(error.getMessage().contains(str(v.get("expectErrorContains"))), error.getMessage());
            } else {
                assertEquals(v.get("expectResult"), run.get());
            }
            if (v.containsKey("expectRequest")) {
                Map<String, Object> expected = map(v.get("expectRequest"));
                FakeHttpClient.Call call = http.calls.get(0);
                if (expected.containsKey("endpoint")) {
                    assertEquals(expected.get("endpoint"), call.url());
                }
                if (expected.containsKey("method")) {
                    assertEquals(expected.get("method"), call.method());
                }
            }
        }));
    }

    private static void checkRequest(FakeHttpClient.Call call, Map<String, Object> expected, AltiumAuthConfig config) {
        if (expected.containsKey("endpoint")) {
            assertEquals(expected.get("endpoint"), call.url());
        }
        if (expected.containsKey("method")) {
            assertEquals(expected.get("method"), call.method());
        }
        if (expected.containsKey("authorization")) {
            String authorization = str(expected.get("authorization"));
            if (authorization.equals("none")) {
                assertNull(call.header("Authorization"));
            } else if (authorization.startsWith("basic(")) {
                String credentials = config.clientId() + ":" + config.clientSecret().orElseThrow();
                assertEquals("Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)),
                        call.header("Authorization"));
            }
        }
        Map<String, String> form = parseForm(call.body());
        map(expected.getOrDefault("bodyParams", Map.of())).forEach((key, matcher) ->
                assertTrue(matches(form.get(key), matcher), "bodyParam " + key + "=" + form.get(key)));
        strings(expected.getOrDefault("bodyParamsAbsent", List.of())).forEach(key ->
                assertFalse(form.containsKey(key), "bodyParam " + key + " should be absent"));
    }

    private static void assertResultField(Object actual, Object expected, String key) {
        if ("<any>".equals(expected)) {
            assertNotNull(actual, key);
        } else if (expected instanceof String s && s.startsWith("epochWithin:")) {
            String[] parts = s.split(":");
            long target = Instant.now().getEpochSecond() + Long.parseLong(parts[1]);
            assertTrue(Math.abs((Long) actual - target) <= Long.parseLong(parts[2]), key + "=" + actual);
        } else {
            assertEquals(expected, actual, key);
        }
    }

    private static Object tokenField(TokenSet tokens, String key) {
        return switch (key) {
            case "access_token" -> tokens.accessToken();
            case "token_type" -> tokens.tokenType();
            case "expires_in" -> tokens.expiresIn();
            case "expires_at" -> tokens.expiresAt();
            case "refresh_token" -> tokens.refreshToken();
            case "id_token" -> tokens.idToken();
            case "scope" -> tokens.scope();
            default -> throw new AssertionError("unknown result field " + key);
        };
    }

    private static boolean matches(String actual, Object matcher) {
        if ("<any>".equals(matcher)) {
            return actual != null;
        }
        if (matcher instanceof String s && s.startsWith("contains:")) {
            return actual != null && actual.contains(s.substring("contains:".length()));
        }
        return matcher.equals(actual);
    }

    private static AltiumAuthConfig config(Map<String, Object> c) {
        AltiumEndpoints defaults = AltiumEndpoints.COMMERCIAL_CLOUD;
        AltiumEndpoints endpoints = new AltiumEndpoints(
                (String) c.getOrDefault("authEndpoint", defaults.authorizeEndpoint()),
                (String) c.getOrDefault("tokenEndpoint", defaults.tokenEndpoint()),
                (String) c.getOrDefault("actionWaitEndpoint", defaults.actionWaitEndpoint()),
                (String) c.getOrDefault("redirectUri", defaults.redirectUri()));
        AltiumAuthConfig.Builder builder = AltiumAuthConfig.builder(str(c.get("clientId")), str(c.get("scopes")))
                .endpoints(endpoints)
                .openBrowser(url -> { });
        if (c.containsKey("clientSecret")) {
            builder.clientSecret(str(c.get("clientSecret")));
        }
        return builder.build();
    }

    private static FakeHttpClient replying(Map<String, Object> mock) {
        FakeHttpClient.Reply reply = mockReply(mock);
        return new FakeHttpClient(call -> reply);
    }

    private static FakeHttpClient unusedHttp() {
        return new FakeHttpClient(call -> {
            throw new AssertionError("unexpected request to " + call.url());
        });
    }

    private static FakeHttpClient.Reply mockReply(Map<String, Object> mock) {
        int status = ((Number) mock.get("status")).intValue();
        String body = mock.containsKey("json") ? Json.write(mock.get("json")) : (String) mock.getOrDefault("text", "");
        return new FakeHttpClient.Reply(status, body);
    }

    private static Map<String, String> parseForm(String encoded) {
        Map<String, String> form = new HashMap<>();
        if (encoded == null || encoded.isEmpty()) {
            return form;
        }
        for (String pair : encoded.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            form.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return form;
    }

    private static Map<String, Object> loadVectors() {
        try {
            return map(Json.parse(Files.readString(Path.of("../../spec/conformance/vectors.json"))));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Stream<Map<String, Object>> vectors(String group) {
        return list(VECTORS.get(group)).stream().map(ConformanceTest::map);
    }

    private static String id(Map<String, Object> vector) {
        return str(vector.get("id"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object value) {
        return (List<Object>) value;
    }

    private static Stream<String> strings(Object value) {
        return list(value).stream().map(String.class::cast);
    }

    private static String str(Object value) {
        return (String) value;
    }
}
