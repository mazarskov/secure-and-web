# Bundled development HTTPS certificate

These two PEM files are intentionally committed for the local course demo.
The private key is public: never use this certificate/key pair for deployment
or real credentials. No certificate tool or trust-store installation is required
to run the app. Accept the self-signed certificate warning at the local URL.

The certificate is valid from 4 November 2026 to 1 November 2036 (UTC), for
`localhost`, `127.0.0.1`, and `::1`. Its long lifetime is for demo convenience.

To replace it, install OpenSSL and run this single command from
`web-app-security`, then restart the server (and accept the new browser warning):

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 -keyout certs/dev/localhost-key.pem -out certs/dev/localhost.pem -subj "/CN=localhost/O=Course Demo Development Only" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth"
```

Update the validity dates in this document when regenerating the certificate.
Only these specific development files are allowed by `.gitignore`; additional
local certificate files remain ignored. Express serves only `public/`, keeping
these files outside the web directory.
