# gravitee-am-extensiongrant-id-jag

A [Gravitee Access Management](https://www.gravitee.io/platform/access-management) extension grant that accepts an
**Identity Assertion JWT Authorization Grant (ID-JAG)** at the token endpoint. It lets an AM security domain act as
the authorization server for an MCP server that uses
[MCP enterprise-managed authorization](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization),
for example Claude's [Enterprise Managed Auth](https://claude.com/docs/connectors/building/enterprise-managed-auth)
with Claude-issued assertions. Users get a token with no sign-in screen and no per-connector consent.

```
POST /{domain}/oauth/token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&assertion=<ID-JAG>
&client_id=…&client_secret=…
&resource=https://mcp.example.com/mcp   (optional, RFC 8707)
```

## Why not AM's built-in JWT-bearer grant

AM's `jwtbearer-am-extension-grant` checks the signature and expiry only. An ID-JAG must also be bound to *this*
authorization server and client, and accepted once. Without those checks, any other authorization server that
receives assertions from the same issuer could replay them here. The built-in grant also finds users by `sub`, which
is opaque in Claude-issued assertions; users have to be found by email.

## What it checks

Every check refuses with `invalid_grant`, and they run in this order:

1. The assertion is a compact JWS. `alg` is `ES256` or `RS256`, never `none` or HMAC. `typ` is `oauth-id-jag+jwt`.
2. `iss` equals the configured issuer exactly. This is checked before any key is fetched.
3. The signature verifies with a key from `<iss>/.well-known/openid-configuration` → `jwks_uri`, and that document's
   `issuer` must equal `iss`.
   - Keys in the assertion header (`jwk`, `jku`, `x5u`) are ignored.
   - RSA keys must be at least 2048 bits.
   - An unseen `kid` triggers at most one refetch every 30 s.
4. `aud` is exactly one value: this domain's issuer.
5. `client_id` equals the client on the token request.
6. `sub` and `email` are present.
7. `exp`, `iat` and `nbf` hold, with 60 s of skew (configurable). `exp − iat` must be at most 300 s (configurable).
8. Optional checks, applied only when configured or when the assertion carries the claim:
   - `aud_tenant` must match the configured tenant;
   - the requested scopes must be within the assertion's `scope`;
   - the email's domain must be on the allow-list.
9. `jti` is present and has not been used before. This check runs last, so a refused assertion doesn't use up its
   `jti`.

Next, the plugin looks the user up. The match is the whole email address, case-insensitive, limited to users whose
`source` is the configured identity provider. There must be exactly one match, and that user must be enabled. The
plugin **never creates users**.

### How the token is issued

The plugin returns the stored user's `externalId`, username, names and dynamic roles. It returns no extra claims.

The extension grant is set to *create users*, with the same identity provider as its identity provider. AM's connect
step then finds that same record by `(externalId, source)` and checks again that the account is enabled. It issues
the token from the stored user, so `sub`, `email` and custom claims (for example SCIM-provisioned attributes read by
`tokenCustomClaims`) are exactly what a normal sign-in produces. The update merges nothing into the record, because
the plugin passes no claims.

## Configuration

Create the extension grant on the security domain:

```json
{
  "type": "id-jag-am-extension-grant",
  "name": "Claude-issued ID-JAG",
  "grantType": "urn:ietf:params:oauth:grant-type:jwt-bearer",
  "identityProvider": "<id of the provider your users come from>",
  "createUser": true,
  "userExists": false,
  "configuration": "{\"issuer\":\"https://identity.anthropic.com/issuers/<id>\",\"audience\":\"https://auth.example.com/<domain>/oidc\",\"domainId\":\"<domain id>\",\"userSource\":\"<same provider id>\"}"
}
```

Then give each client that may use the grant the grant type
`urn:ietf:params:oauth:grant-type:jwt-bearer~<extension grant id>`.

| Field | Required | Default | Meaning |
|---|---|---|---|
| `issuer` | yes | | The one trusted issuer. Must be `https`. |
| `audience` | yes | | This domain's issuer, exactly as its discovery document publishes it. |
| `domainId` | yes | | This security domain's id, used for the user lookup. |
| `userSource` | yes | | Id of the identity provider users must come from. **Must equal the grant's `identityProvider`.** |
| `dataPlaneId` | | `default` | The data plane holding the domain's users. |
| `tenant` | | | When set, `aud_tenant` must equal it. |
| `allowedEmailDomains` | | | When set, the email's domain must be one of these. |
| `clockSkewSeconds` | | `60` | Skew allowed on `exp`, `iat` and `nbf`. |
| `maxAssertionLifetimeSeconds` | | `300` | Upper bound on `exp − iat`. |
| `allowInsecureIssuer` | | `false` | Accept an `http` issuer. Tests only. |

**`userSource` and `identityProvider` must be the same provider.** If they differ, AM's connect step searches the
wrong provider. It finds nothing and creates a new user. Set both from the same value in your infrastructure code.

## Limits

- **Replay protection is per gateway instance.** `jti` values are remembered in memory until they expire. With
  several gateway replicas, one assertion could be redeemed once per replica within its lifetime, which is under a
  minute for Claude-issued assertions. A confidential client (`client_secret_post`) limits this to whoever holds the
  client's secret.
- **Refresh tokens.** AM issues a refresh token whenever the client also has the `refresh_token` grant. Claude doesn't
  use one from this grant. Give the grant to a client without `refresh_token` if you don't want any.
- **Removing someone from the issuer doesn't revoke tokens already issued.** Keep access tokens short, and disable the
  user in AM (for example through SCIM) so the next exchange is refused.
- Compiled against the AM 4.12.7 API (the newest on Maven Central) and tested end to end against AM **4.12.13**
  (Java 25). The user lookup tries AM's case-insensitive email lookup with the plain address, then exact matches on
  the address as sent and lower-cased, so it doesn't depend on how a given AM version matches the case-insensitive
  lookup. (1.0.0 pre-quoted the address for that lookup. AM 4.12.13 started quoting it itself, so 1.0.0 finds no
  user on 4.12.13 and later.) The plugin uses AM's `DataPlaneRegistry`, an internal API, so re-run the end-to-end
  test before moving to another AM version.

## Build and test

```bash
asdf install                # Java 25, Maven (see .tool-versions)
mvn verify                  # unit tests + the full-stack AM end-to-end test (needs Docker)
```

The plugin zip is `target/gravitee-am-extensiongrant-id-jag-<version>.zip`. Install it in the `plugins` directory of
**both** the AM management API and the gateway, or list its release URL in the Helm chart's `additionalPlugins`.

## Release

Publish a GitHub release tagged with the version, for example `1.0.0`. The release workflow runs the full test suite
and attaches the plugin zip to the release.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

## License

Apache 2.0, see [LICENSE](LICENSE).

---

Maintained by [Fluent Health](https://github.com/Fluent-Health).
