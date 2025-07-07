# this script can read Software Bill of Material (SBOM) data in the CycloneDX
# format and create a CSV file that can be imported with Cypher
import csv
import json
import os
import sys
from os import PathLike
import logging
from datetime import datetime

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")


class SoftwareVulnerabilityData:
    def __init__(self):
        self._data = {}
        self._now = datetime.isoformat(datetime.now())

    def transform(self, folder: PathLike):
        self.__read_dir(folder)
        self.__output_csv("../data/app-sast-findings.csv")

    def __read_dir(self, folder: PathLike):
        logging.info(f"Reading Bearer reports from {folder}")

        try:
            files = [f for f in os.listdir(folder)]
            logging.info(f"Files in {folder}: {files}")

        except FileNotFoundError:
            logging.critical(f"Cannot read directory {folder}")
            sys.exit(1)

        for file in os.listdir(folder):
            if file.endswith("_bearer.json"):
                try:
                    with open(os.path.join(folder, file), "r") as f:
                        data = json.load(f)
                        self.__process_trivy_report(file, data)

                except json.JSONDecodeError:
                    logging.warning(f"Cannot read Bearer file {file}")

    @staticmethod
    def __extract_from_filename(filename: str) -> dict:
        vals = filename.split("_")
        app_name = vals[0]
        app_version = vals[1]

        return {"name": app_name, "app_version": app_version}

    # read a single SBOM in CycloneDX format and save the fields we want
    def __process_trivy_report(self, filename: str, data: dict):
        logging.info(f"Processing Bearer report {filename}")

        # extract the application name and version info from the filename
        meta_data = self.__extract_from_filename(filename)

        # add more data from the SBOM
        meta_data["date"] = self._now
        meta_data["source"] = "bearer"

        # walk through findings
        for severity, findings in data.items():
            for finding in findings:
                fdata = {**meta_data}
                fdata["severity"] = severity
                fdata["cwe"] = finding["cwe_ids"]
                fdata["rule"] = finding["id"]
                fdata["title"] = finding["title"]
                fdata["link"] = finding["documentation_url"]
                fdata["description"] = finding["description"]
                fdata["file"] = finding["full_filename"]

                try:
                    fdata["location"] = "Line{}_Col{}-{}".format(
                        finding["line_number"],
                        finding["source"]["column"]["start"],
                        finding["source"]["column"]["end"]
                    )
                except KeyError:
                    fdata["location"] = ""

                fdata["code"] = finding["code_extract"]

                try:
                    fdata["ref"] = "{}_{}_{}".format(
                        fdata["file"],
                        fdata["location"],
                        finding["fingerprint"]
                    )
                except KeyError:
                    logging.warning(f"Cannot make a unique identifier of the finding {json.dumps(finding)}")
                    continue

                self._data[fdata["ref"]] = fdata

    # store a CSV output file with all the SCA data we extracted
    def __output_csv(self, filename: str):
        logging.info(f"Writing Bearer data to {filename}")

        fields = ["name", "app_version", "date", "source", "severity", "cwe", "rule", "title", "link", "description", "file", "location", "code", "ref"]
        try:
            dictwriter = csv.DictWriter(open(filename, "w"), fieldnames=fields, quoting=csv.QUOTE_ALL, delimiter=";")
            dictwriter.writeheader()
            dictwriter.writerows(self._data.values())
        except IOError:
            logging.critical(f"Cannot write to {filename}")
            sys.exit(1)

if __name__ == "__main__":
    sbom_data = SoftwareVulnerabilityData()
    sbom_data.transform(sys.argv[1])
