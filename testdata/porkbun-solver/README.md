# Solver testdata directory

Create manifest with the needed secrets:

```
apiVersion: v1
kind: Secret
metadata:
  name: porkbun-secret
type: Opaque
data:
  api-key: YOUR_BASE64_API_KEY
  secret-api-key: YOUR_BASE64_SECRET_API_KEY
```

Create config.json, which will be used for the challenge request config:

```
{
  "apiKeySecretRef": {
    "name": "porkbun-secret",
    "key": "api-key"
  },
  "secretKeySecretRef": {
    "name": "porkbun-secret",
    "key": "secret-key"
  }
}
```
