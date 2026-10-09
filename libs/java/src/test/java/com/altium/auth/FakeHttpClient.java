package com.altium.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

final class FakeHttpClient extends HttpClient {
    record Call(String method, String url, HttpHeaders headers, String body) {
        String header(String name) {
            return headers.firstValue(name).orElse(null);
        }
    }

    record Reply(int status, String body) {
    }

    interface Responder {
        Reply respond(Call call) throws IOException;
    }

    final List<Call> calls = new CopyOnWriteArrayList<>();
    private final Responder responder;

    FakeHttpClient(Responder responder) {
        this.responder = responder;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        Call call = new Call(request.method(), request.uri().toString(), request.headers(), bodyOf(request));
        calls.add(call);
        try {
            @SuppressWarnings("unchecked")
            HttpResponse<T> response = (HttpResponse<T>) new Response(request, responder.respond(call));
            return CompletableFuture.completedFuture(response);
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        return sendAsync(request, handler);
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        throw new UnsupportedOperationException("the client only uses sendAsync");
    }

    private static String bodyOf(HttpRequest request) {
        return request.bodyPublisher().map(publisher -> {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            CompletableFuture<Void> done = new CompletableFuture<>();
            publisher.subscribe(new Flow.Subscriber<ByteBuffer>() {
                @Override
                public void onSubscribe(Flow.Subscription subscription) {
                    subscription.request(Long.MAX_VALUE);
                }

                @Override
                public void onNext(ByteBuffer buffer) {
                    byte[] bytes = new byte[buffer.remaining()];
                    buffer.get(bytes);
                    out.writeBytes(bytes);
                }

                @Override
                public void onError(Throwable error) {
                    done.completeExceptionally(error);
                }

                @Override
                public void onComplete() {
                    done.complete(null);
                }
            });
            done.join();
            return out.toString(StandardCharsets.UTF_8);
        }).orElse("");
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return Optional.empty();
    }

    @Override
    public Redirect followRedirects() {
        return Redirect.NEVER;
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
        try {
            return SSLContext.getDefault();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public SSLParameters sslParameters() {
        return new SSLParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return Optional.empty();
    }

    @Override
    public Version version() {
        return Version.HTTP_1_1;
    }

    @Override
    public Optional<Executor> executor() {
        return Optional.empty();
    }

    private record Response(HttpRequest request, Reply reply) implements HttpResponse<String> {
        @Override
        public int statusCode() {
            return reply.status();
        }

        @Override
        public Optional<HttpResponse<String>> previousResponse() {
            return Optional.empty();
        }

        @Override
        public HttpHeaders headers() {
            return HttpHeaders.of(Map.of(), (name, value) -> true);
        }

        @Override
        public String body() {
            return reply.body();
        }

        @Override
        public Optional<SSLSession> sslSession() {
            return Optional.empty();
        }

        @Override
        public URI uri() {
            return request.uri();
        }

        @Override
        public Version version() {
            return Version.HTTP_1_1;
        }
    }
}
