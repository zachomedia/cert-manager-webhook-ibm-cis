# IBM CIS cert-manager ACME webhook

## Installing

To install with helm, run:

```bash
$ git clone https://github.com/zachomedia/cert-manager-webhook-ibm-cis.git
$ cd cert-manager-webhook-ibm-cis/deploy/cert-manager-webhook-ibm-cis
$ helm install --name cert-manager-webhook-ibm-cis .
```

Without helm, run:

```bash
$ make rendered-manifest.yaml
$ kubectl apply -f _out/rendered-manifest.yaml
```

### Issuer/ClusterIssuer

An example issuer:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cis-api-key
type: Opaque
data:
  key: APIKEY_BASE64
---
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    email: certmaster@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-staging-account-key
    dns01:
      providers:
        - name: dns
          webhook:
            groupName: acme.zacharyseguin.ca
            solverName: cis
            config:
              crn: ciscrn
              apiKeySecretRef:
                name: cis-api-key
                key: key

              # Optional config, shown with default values
              #   all times in seconds
              timeout: 30
```

And then you can issue a cert:

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: test-cert
  namespace: default
spec:
  secretName: example-com-tls
  commonName: example.com
  dnsNames:
  - example.com
  - www.example.com
  issuerRef:
    name: letsencrypt-staging
    kind: Issuer
  acme:
    config:
      - dns01:
          provider: dns
        domains:
          - example.com
          - www.example.com
```

## Development

### Running the test suite

You can run the test suite with:

1. Copy `testdata/cis/apikey.yml.sample` and `testdata/cis/config.json.sample` and fill in the appropriate values

```bash
$ ./scripts/fetch-test-binaries.sh
$ TEST_ZONE_NAME=example.com. go test .
```
