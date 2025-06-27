## Create SBOMs from software projects

We will be making SBOMs in the CycloneDX format for all software projects.
<br/>

### Python

First install cyclonedx-py, see [Documentation on Github](https://github.com/CycloneDX/cyclonedx-python)

Then run it on your virtual environment
```shell
cyclonedx-py venv > sbom.json
```

Or requirements.txt
```shell
cyclonedx-py requirements > sbom.json
```

Or poetry
```shell
cyclonedx-py poetry > sbom.json
```

### Java projects

First install OpenJDK 17, gradle and maven.

Then install cdxgen, an NPM package, into a global NPM directory

```shell
npm install -h @cyclonedx/cdxgen
```

```shell
cdxgen --enable-native-access=ALL-UNNAMED -t java --json-pretty -o sbom.json
```


### Go projects

```shell
cdxgen -t go --json-pretty -o Alphazap_8.1_sbom.json
```


### Javascript projects

Install cdxgen, an NPM package, into a global NPM directory

```shell
npm install -h @cyclonedx/cdxgen
```

```shell
cdxgen -t npm --json-pretty -o Trippledex_18.0_sbom.json
```
