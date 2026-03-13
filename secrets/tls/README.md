# TLS Certificates

Place runtime TLS assets for `netwatch-edge` in this directory:

- `tls.crt` (server certificate, ideally full chain)
- `tls.key` (server private key)

For local lab/dev only, you can create a self-signed pair:

```bash
mkdir -p secrets/tls
openssl req -x509 -nodes -newkey rsa:4096 \
  -days 365 \
  -keyout secrets/tls/tls.key \
  -out secrets/tls/tls.crt \
  -subj "/CN=localhost"
```