package com.altium.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class TransportTest {
    private final CountDownLatch release = new CountDownLatch(1);
    private final AtomicInteger polls = new AtomicInteger();
    private HttpServer server;
    private ServerSocket plainTextServer;

    @AfterEach
    void stopServers() throws IOException {
        release.countDown();
        if (server != null) {
            server.stop(0);
        }
        if (plainTextServer != null) {
            plainTextServer.close();
        }
    }

    @Test
    void signInFailsFastWhenTheNetworkIsUnreachable() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        AltiumAuthClient client = client("http://127.0.0.1:" + closedPort);

        assertTimeoutPreemptively(Duration.ofSeconds(10), () ->
                assertThrows(TransportException.class, () -> client.signIn(WorkspaceSelection.NONE, Duration.ofSeconds(60))));
    }

    @Test
    void signInFailsFastOnATlsFailure() throws IOException {
        AltiumAuthClient client = client("https://127.0.0.1:" + startPlainTextServer());

        ActionWaitException error = assertTimeoutPreemptively(Duration.ofSeconds(10), () ->
                assertThrows(ActionWaitException.class, () -> client.signIn(WorkspaceSelection.NONE, Duration.ofSeconds(60))));

        assertTrue(error.getMessage().contains("TLS"), error.getMessage());
    }

    @Test
    void tokenRequestSurfacesATlsFailureAsTlsException() throws IOException {
        AltiumAuthClient client = client("https://127.0.0.1:" + startPlainTextServer());

        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> assertThrows(TlsException.class, () -> client.refreshToken("RT")));
    }

    @Test
    void signInTimesOutWhenNoResultArrives() throws IOException {
        startServer(this::hang);
        AltiumAuthClient client = client("http://127.0.0.1:" + server.getAddress().getPort());

        ActionWaitException error = assertTimeoutPreemptively(Duration.ofSeconds(10), () ->
                assertThrows(ActionWaitException.class, () -> client.signIn(WorkspaceSelection.NONE, Duration.ofSeconds(1))));

        assertTrue(error.getMessage().contains("timed out"), error.getMessage());
    }

    @Test
    void interruptingSignInAbortsTheLongPoll() throws Exception {
        startServer(this::hang);
        AltiumAuthClient client = client("http://127.0.0.1:" + server.getAddress().getPort());
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        AtomicReference<Boolean> stillInterrupted = new AtomicReference<>();
        Thread signIn = new Thread(() -> {
            try {
                client.signIn(WorkspaceSelection.NONE, Duration.ofSeconds(60));
            } catch (RuntimeException e) {
                thrown.set(e);
                stillInterrupted.set(Thread.currentThread().isInterrupted());
            }
        });

        signIn.start();
        waitForPoll();
        signIn.interrupt();
        signIn.join(5_000);

        assertFalse(signIn.isAlive(), "signIn did not return after interrupt");
        assertInstanceOf(TransportException.class, thrown.get());
        assertTrue(stillInterrupted.get(), "interrupt flag should be restored");
    }

    @Test
    void reconnectsOver408AndSendsTheProductUserAgent() throws IOException {
        AtomicReference<String> userAgent = new AtomicReference<>();
        startServer(exchange -> {
            userAgent.set(exchange.getRequestHeaders().getFirst("User-Agent"));
            if (exchange.getRequestURI().getPath().endsWith("/await")) {
                String token = (String) ((Map<?, ?>) Json.parse(read(exchange))).get("token");
                if (polls.incrementAndGet() == 1) {
                    respond(exchange, 408, "");
                } else {
                    respond(exchange, 200, "{\"data\":{\"code\":\"c\",\"state\":\"" + token + "\"}}");
                }
            } else {
                respond(exchange, 200, "{\"access_token\":\"AT\",\"token_type\":\"Bearer\"}");
            }
        });
        AltiumAuthClient client = client("http://127.0.0.1:" + server.getAddress().getPort());

        assertEquals("AT", client.signIn(WorkspaceSelection.NONE, Duration.ofSeconds(10)).accessToken());
        assertEquals(2, polls.get());
        assertTrue(userAgent.get().startsWith("altium-auth-jvm"), userAgent.get());
        assertFalse(userAgent.get().toLowerCase(Locale.ROOT).contains("java"), userAgent.get());
    }

    private AltiumAuthClient client(String origin) {
        return new AltiumAuthClient(AltiumAuthConfig.builder("c", "openid profile")
                .endpoints(AltiumEndpoints.aes(origin))
                .openBrowser(url -> { })
                .build());
    }

    private void startServer(Handler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/", exchange -> {
            try {
                handler.handle(exchange);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        server.start();
    }

    private int startPlainTextServer() throws IOException {
        plainTextServer = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            while (!plainTextServer.isClosed()) {
                try (Socket socket = plainTextServer.accept()) {
                    socket.getOutputStream().write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                } catch (IOException closed) {
                    return;
                }
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();
        return plainTextServer.getLocalPort();
    }

    private void hang(HttpExchange exchange) throws InterruptedException {
        polls.incrementAndGet();
        release.await();
    }

    private void waitForPoll() throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (polls.get() == 0 && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertEquals(1, polls.get(), "the poll never reached the server");
    }

    private static String read(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    private interface Handler {
        void handle(HttpExchange exchange) throws IOException, InterruptedException;
    }
}
