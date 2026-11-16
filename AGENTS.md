# Agent guidance — gravitee-am-extensiongrant-id-jag

## Verification rule (non-negotiable)

**Never claim the grant works, is fixed or is verified until `IdJagAmE2EIT` has passed in this working tree.** `mvn test` exercises the validator against WireMock only. The authoritative check boots AM (management API and gateway), MongoDB and a WireMock issuer as real containers, then drives AM's token endpoint:

```bash
mvn verify
```

Do **not** pass `-DskipTests=true` to `verify`, because failsafe then skips the IT silently. If Docker is unavailable, say so explicitly rather than reporting success.

## Things that are easy to break

- **The validator's check order is part of the security model.** `iss` is checked before any key is fetched, and `jti` is consumed last. Keep the numbered list in `IdJagValidator`'s Javadoc and the README in step with the code.
- **The principal returned by the provider carries no additional information on purpose.** AM's connect step merges it over the stored user, so anything put there overwrites SCIM- or IdP-written attributes.
- **`userSource` must equal the extension grant's `identityProvider`.** If they differ, connect misses the user and creates one. The plugin cannot see the grant's provider id, so this is documented and must be set from one value by whoever configures it.
- **AM internals.** `DataPlaneRegistry` is resolved from the plugin context's parent (the gateway's node context). Re-run the IT against any new AM version before bumping `gravitee-am.version` and the IT's `am.version`.

## Repo conventions

- Java 25 (AM 4.12's class-file level), Maven, JUnit 5, AssertJ, WireMock and Testcontainers.
- Everything AM ships (nimbus, rxjava, spring, AM APIs) is `provided`, so the zip's `lib/` stays empty.
- `prettier-maven-plugin` checks formatting in `validate`. To fix it: `mvn com.hubspot.maven.plugins:prettier-maven-plugin:0.22:write -DprettierJavaVersion=2.6.4 -DprintWidth=120 -DtabWidth=4`.
