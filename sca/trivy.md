## Using Trivy for Software Composition Analysis data

#### Install trivy
[Official Documentation: getting started](https://trivy.dev/latest/getting-started/#examples)

#### Run Trivy on the SBOMs

```
trivy sbom sbom.json -f json -o trivy-report.json
```

