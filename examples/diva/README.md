# DIVA Android demonstration assessment

This directory contains a sanitized Astranyx assessment generated from a real
MobSF static scan of DIVA Android, an intentionally vulnerable training app.
It is demonstration material, not a penetration-test report for a production
application.

## Provenance

- Application: DIVA Android (`jakhar.aseem.diva`, version 1.0)
- OWASP reference ID: `MASTG-APP-0007`
- Publisher source: <https://github.com/payatu/diva-android>
- Publisher APK archive: <https://payatu.com/wp-content/uploads/2016/01/diva-beta.tar.gz>
- APK SHA-256: `5cefc51fce9bd760b92ab2340477f4dda84b4ae0c5d04a8c9493e4fe34fab7c5`
- Scanner: MobSF 4.5.2
- Container digest: `sha256:6c4083db49d7894574052652ffd4c7a90cdebaa59653e696d396d54f493bc87a`

The APK and raw MobSF JSON are deliberately excluded. The committed bundle
contains normalized findings and presentation assets only. It does not contain
MobSF credentials, local filesystem paths, raw application source, or an APK.

## Review status

Six package or manifest facts were confirmed by static inspection. All other
items remain `needs_validation`; no dynamic exploitation was performed. The
example therefore demonstrates Astranyx's review gate without presenting
scanner output as automatically proven vulnerability impact.

## Verify the sealed bundle

```console
astranyx verify examples/diva/assessment
```

Open `assessment/index.html` locally to view the client-facing report. Copy
`assessment/reviews.template.json` outside the sealed directory before adding
new review decisions, then regenerate the assessment with `--review-file`.

## Reproduce

Run MobSF locally against the exact APK hash above, export its JSON report, and
then run:

```console
astranyx assess mobsf-report.json \
  --output examples/diva/assessment \
  --client "Demonstration Client" \
  --consultant "Astranyx Security" \
  --assessment-title "DIVA Android Security Assessment" \
  --review-file reviews.json
```

Generated timestamps and manifest hashes will change on reproduction.
