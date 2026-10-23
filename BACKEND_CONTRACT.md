# Lumen backend integration contract

The frontend is a browser client for a server-side gateway. The custom Lumen engine, signing keys, AWS identity, and tool implementations belong behind the API. Do not import Python engine modules into the Next.js app or put their secrets in `NEXT_PUBLIC_*` values.

## Request path

```text
Browser → Supabase Google OAuth → Supabase access token
       → Python HTTP bridge → Lumen policy/engine adapter → approved tools
```

The browser sends its Supabase access token as `Authorization: Bearer <token>`. The server must validate the signature, issuer, expiry, and subject before dispatching any tool. Use Supabase’s current signing-key/JWKS flow (or another supported JWT verification library); do not trust a decoded JWT without verifying it. See the [Supabase JWT guide](https://supabase.com/docs/guides/auth/jwts).

## Required routes

### `POST /api/v1/gateway/proxy`

Headers:

```http
Authorization: Bearer <Supabase access token>
Content-Type: application/json
```

Body:

```json
{
  "toolName": "query_secure_records",
  "arguments": { "recordId": "REC-1001", "fields": ["owner", "ssn", "wire"] },
  "priority": "NORMAL",
  "clearanceOverride": false
}
```

Validate the shape and allowlist the tool name and argument schema before passing the call to the custom engine. Treat `priority` as a scheduling request. Never let a client-provided `clearanceOverride` grant access; the server decides authorization and approval policy. Return only a sanitized JSON response, for example `{ "resultType": "success", "records": [], "elapsed_us": 8.04 }`.

The sandbox uses these tool names from the supplied brief:

- `query_secure_records` for both the authorized query and the injection attempt (the latter passes a hostile `recordId` that the server must reject).
- `create_vendor_payout` with a `$25,000` amount; the server should return `resultType: "input_required"` and a stable approval/challenge identifier without executing the payout.
- `run_fraud_detection_model` for the model scenario.

The frontend currently displays the high-value approval response in a modal. It does not yet submit an approval decision; a real approval flow needs a server-side challenge/approve endpoint and explicit identity/MFA verification before continuation.

### `GET /api/export?format=...`

Accept `aws_bedrock`, `csv`, `ndjson`, `mcp_config`, or `compliance_report`. Require and validate the same bearer token. Return the export body with a matching `Content-Type` and, where useful, a `Content-Disposition` filename.

### `GET /api/v1/sdk/download`

Require and validate the bearer token. Return `lumen_client_sdk_bundle.zip` as `application/zip` with a download filename.

### Recommended `GET /health`

Return service health and version only. Do not expose secrets, environment values, IAM role identifiers, or internal tool output.

## Deployment requirements

1. Deploy the Python bridge to an HTTPS address reachable by the deployed frontend. Set `NEXT_PUBLIC_LUMEN_API_URL` to that public base URL; `127.0.0.1` is only a local-development default.
2. Configure CORS on the bridge for the exact local and Vercel frontend origins. Allow `GET`, `POST`, `OPTIONS` and the `Authorization` and `Content-Type` headers.
3. Keep `LUMEN_HMAC_SECRET`, AWS credentials/role binding, and any service-role key in server-side secret storage only.
4. Configure the same active Supabase project URL as the frontend and in the gateway’s JWT verifier. If Supabase is replaced, update both sides together.
5. Enable Google in Supabase Auth, configure its OAuth credentials, and add each frontend origin's `/auth/callback` URL to the Auth redirect allow list. Set the matching frontend origin as the Supabase Auth Site URL for email verification and password recovery links.
6. Replace the portal’s local fallback examples and fixed marketing telemetry with real gateway responses/metrics before presenting them as production data.

## Current integration boundary

This frontend implements the HTTP client and preview experience, but the actual Lumen Python bridge and engine are not present in this delivery. The currently discoverable local `connectAI` repository is a JEE CBT/desktop application, not the Lumen backend. The frontend cannot become a live gateway client until the custom engine is available and the required routes are implemented or mapped to its existing API.
