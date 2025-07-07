# get SCA data into the CSV file format


In order to transform CycloneDX SBOM data and Trivy reports into CSV use:

```shell
python3 ./sbom_csv.py ../raw_data
python3 ./vulnerability_csv.py ../raw_data
```
