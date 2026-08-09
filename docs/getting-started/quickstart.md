# Quickstart

## 1. Install

```sh
curl -sSfL https://github.com/mental-lab/suture/releases/latest/download/suture_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz | tar xz suture
sudo install suture /usr/local/bin/
```

Verify the release before installing it — checksums are cosign keyless-signed:

```sh
curl -sSfLO https://github.com/mental-lab/suture/releases/latest/download/checksums.txt{,.sig,.pem}
cosign verify-blob --signature checksums.txt.sig --certificate checksums.pem \
  --certificate-identity-regexp github.com/mental-lab/suture \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
```

## 2. Scan something

Suture reads scanner output; it is not itself a scanner. Either scanner works:

```sh
grype dir:. -o json --file fs-scan.json        # or: trivy fs . -f json -o fs-scan.json
```

## 3. Advise

```sh
suture advise --scan-dir . --format markdown --out vex-report.md
```

Add exposure context so the decision framework can weigh internet-facing
findings:

```yaml
# asset-inventory.yaml
assets:
  my-service:
    internet_exposed: true
```

```sh
suture advise --scan-dir . --assets asset-inventory.yaml --out vex-report.md
```

## 4. Fetch the fix cache (and VEX-aware scanning)

```sh
suture fetch --sbom sbom.json --out data/vex-cache.json --write-docs vex-documents
grype dir:. --vex vex-documents   # findings Chainguard marked fixed are suppressed
```

## 5. Gate in CI

```sh
suture policy export --dir policy/vex --asset-key my-service
conftest test fs-scan.json --policy policy/vex --all-namespaces \
  --data assets.json --data vex.json   # see README "CI usage" for the jq/yq reshaping
```

A full working pipeline lives in
[chainguard-swag-shop](https://github.com/mental-lab/chainguard-swag-shop):
`.github/workflows/security.yml` runs build → test → scan → advise → gate.
