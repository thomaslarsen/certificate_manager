# Storage managers

The PKI API makes use of two storage mechnisms:

- `SecretManager` - used to store sensitive data, that is private to the API
- `CertificateManager` - used to store issued certificates

Each of the managers stores data in a key/value format, where the key can optionally be prefixed with a path. When a path is used, it is provided in an optional `path` parameter.

## Structure

The following objects are stored in the managers:

| Manager | Object | Key | Path | Format |
|---|---|---|---|---|
| Secret | CA private key | `private` | \<CA name> | bytes (PEM) |
| Secret | CA parent name | `parent` | \<CA name> | string |
| Certificate | CA certificate | \<CA name> | | bytes (PEM) |
| Certificate | EA certificate | \<serial> | | bytes (PEM) |
| Certificate | CA role | \<role name> | roles/\<CA name> | string (JSON) |
| Certificate | Client recipient | `client` | clients/\<client name> | string (JSON) |
| Certificate | Client recipient role | \<role name> | clients/\<client name>/roles | string (JSON) |
| Certificate | Client certificate | \<CN> | clients/\<client name>/certs | bytes (PEM) |
