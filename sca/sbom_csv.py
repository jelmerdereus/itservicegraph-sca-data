# this script can read Software Bill of Material (SBOM) data in the CycloneDX
# format and create a CSV file that can be imported with Cypher
import csv
import json
import os
import sys
from os import PathLike
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")


class SbomData:
    def __init__(self):
        self._data = []
        self._direct_components = set()

    def transform(self, folder: PathLike):
        self.__read_dir(folder)
        self.__output_csv("../data/app-sbom.csv")

    def __read_dir(self, folder: PathLike):
        logging.info(f"Reading SBOM data from {folder}")

        try:
            files = [f for f in os.listdir(folder)]
            logging.info(f"Files in {folder}: {files}")

        except FileNotFoundError:
            logging.critical(f"Cannot read directory {folder}")
            sys.exit(1)

        for file in os.listdir(folder):
            if file.endswith("_sbom.json"):
                try:
                    with open(os.path.join(folder, file), "r") as f:
                        data = json.load(f)
                        self.__process_sbom(file, data)

                except json.JSONDecodeError:
                    logging.warning(f"Cannot read SBOM file {file}")

    @staticmethod
    def __extract_from_filename(filename: str) -> dict:
        vals = filename.split("_")
        app_name = vals[0]
        app_version = vals[1]

        return {"name": app_name, "app_version": app_version}

    # read a single SBOM in CycloneDX format and save the fields we want
    def __process_sbom(self, filename: str, data: dict):
        logging.info(f"Processing SBOM from {filename}")

        # extract the application name and version info from the filename
        meta_data = self.__extract_from_filename(filename)

        # add more data from the SBOM
        meta_data["date"] = data["metadata"]["timestamp"]
        meta_data["source"] = data["metadata"]["tools"]["components"][0]["name"]

        # direct dependencies
        if "component" in data["metadata"]:
            direct_components = data["metadata"]["component"].get("components", [])

            for component in direct_components:
                sca_data = {**meta_data}
                sca_data["component"] = component["name"].split("/")[-1]
                sca_data["component_version"] = component["version"]
                sca_data["purl"] = component["purl"]
                sca_data["transitive"] = "false"

                self._direct_components.add(component["purl"])
                self._data.append(sca_data)

        # all dependencies, including transitive
        for component in data["components"]:
            sca_data = {**meta_data}

            # skip direct dependencies
            if component["purl"] in self._direct_components:
                continue

            sca_data["component"] = component["name"].split("/")[-1]
            sca_data["component_version"] = component["version"]
            sca_data["purl"] = component["purl"]

            sca_data["transitive"] = "false"
            if len(self._direct_components) != 0:
                sca_data["transitive"] = "true"

            self._data.append(sca_data)

    # store a CSV output file with all the SCA data we extracted
    def __output_csv(self, filename: str):
        logging.info(f"Writing SBOM data to {filename}")

        fields = ["name", "app_version", "date", "source", "component", "component_version", "purl", "transitive"]
        try:
            dictwriter = csv.DictWriter(open(filename, "w"), fieldnames=fields)
            dictwriter.writeheader()
            dictwriter.writerows(self._data)
        except IOError:
            logging.critical(f"Cannot write to {filename}")
            sys.exit(1)

if __name__ == "__main__":
    sbom_data = SbomData()
    sbom_data.transform(sys.argv[1])
