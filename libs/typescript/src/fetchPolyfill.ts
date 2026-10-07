/**
 * Minimal POST helpers over the global `fetch`.
 *
 * `fetch` is available in every supported runtime (Node ≥20, browsers, Bun,
 * Deno, bundlers), so no fallback transport is needed. The response body is
 * read once and buffered so callers can inspect it as both text and JSON —
 * useful for error paths that fall back from `json()` to the raw body.
 */

interface HttpResponse {
  status: number;
  text(): string;
  json<T = unknown>(): T;
}

async function post(
  endpoint: string,
  contentType: string,
  body: string,
  signal?: AbortSignal,
  extraHeaders?: Record<string, string>,
): Promise<HttpResponse> {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": contentType, ...extraHeaders },
    body,
    signal,
  });

  const text = await res.text();
  return {
    status: res.status,
    text: () => text,
    json: <T = unknown>(): T => (text ? JSON.parse(text) : null) as T,
  };
}

/** POST a JSON body. */
export function postJson(
  endpoint: string,
  bodyObj: unknown,
  signal?: AbortSignal,
): Promise<HttpResponse> {
  return post(endpoint, "application/json", JSON.stringify(bodyObj), signal);
}

/** POST a form-encoded body, with optional extra request headers. */
export function postForm(
  endpoint: string,
  formBody: Record<string, string>,
  signal?: AbortSignal,
  headers?: Record<string, string>,
): Promise<HttpResponse> {
  return post(
    endpoint,
    "application/x-www-form-urlencoded",
    new URLSearchParams(formBody).toString(),
    signal,
    headers,
  );
}

// https://github.com/nodejs/node/blob/main/doc/api/tls.md#x509-certificate-error-codes
const TLS_ERROR_CODES = new Set([
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_CRL",
  "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
  "UNABLE_TO_DECRYPT_CRL_SIGNATURE",
  "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
  "CERT_SIGNATURE_FAILURE",
  "CRL_SIGNATURE_FAILURE",
  "CERT_NOT_YET_VALID",
  "CERT_HAS_EXPIRED",
  "CRL_NOT_YET_VALID",
  "CRL_HAS_EXPIRED",
  "ERROR_IN_CERT_NOT_BEFORE_FIELD",
  "ERROR_IN_CERT_NOT_AFTER_FIELD",
  "ERROR_IN_CRL_LAST_UPDATE_FIELD",
  "ERROR_IN_CRL_NEXT_UPDATE_FIELD",
  "OUT_OF_MEM",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "CERT_CHAIN_TOO_LONG",
  "CERT_REVOKED",
  "INVALID_CA",
  "PATH_LENGTH_EXCEEDED",
  "INVALID_PURPOSE",
  "CERT_UNTRUSTED",
  "CERT_REJECTED",
  "HOSTNAME_MISMATCH",
]);

const REQUEST_TIMEOUT_CODES = new Set(["UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT"]);

function hasCodeInChain(err: unknown, codes: Set<string>): err is Error {
  for (let e: unknown = err; e instanceof Error; e = (e as { cause?: unknown }).cause) {
    if ("code" in e && codes.has(String((e as { code?: unknown }).code))) {
      return true;
    }
  }
  return false;
}

/** True when a TLS/certificate failure appears anywhere in the error's cause chain. */
export function isTlsError(err: unknown): err is Error {
  return hasCodeInChain(err, TLS_ERROR_CODES);
}

/** True when the HTTP client's own request timeout fired, rather than the network failing. */
export function isRequestTimeout(err: unknown): err is Error {
  return hasCodeInChain(err, REQUEST_TIMEOUT_CODES);
}
