# Contributing

Thanks for your interest in contributing.

## Reporting bugs

Open an issue describing the problem, how to reproduce it, the AM version you run, and what you expected. Report security issues privately instead, as [SECURITY.md](./SECURITY.md) describes.

## Proposing changes

1. Fork the repository.
2. Create a branch: `git checkout -b my-fix`.
3. Make your changes and commit with a clear message.
4. Run `mvn verify`. This runs the unit tests and the full-stack end-to-end test against a real Gravitee AM, which needs Docker. A change that touches validation needs a test for the new or changed check.
5. Open a pull request against `main`.

## Code style

Java 25, formatted with prettier-java; `mvn verify` fails on unformatted code. To format:

```bash
mvn com.hubspot.maven.plugins:prettier-maven-plugin:0.22:write -DprettierJavaVersion=2.6.4 -DprintWidth=120 -DtabWidth=4
```

Keep the order of checks in `IdJagValidator` and the README's "What it checks" list in step.

## No CLA required

You do not need to sign a Contributor License Agreement. By submitting a pull request, you agree to license your contribution under the repository's existing [LICENSE](./LICENSE).
