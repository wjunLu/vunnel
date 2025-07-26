from __future__ import annotations

import copy
import logging
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING, Any

import os
import requests
from tqdm import tqdm

from vunnel.utils import http_wrapper as http
from vunnel.utils.vulnerability import vulnerability_element

if TYPE_CHECKING:

    from vunnel import workspace

NAMESPACES = {
    "cvrf": "http://www.icasi.org/CVRF/schema/cvrf/1.1",
    "prod": "http://www.icasi.org/CVRF/schema/prod/1.1",
    "vuln": "http://www.icasi.org/CVRF/schema/vuln/1.1",
}

class Parser:
    _cvrf_dir = "cvrf"
    _cvrf_index = "index.txt"

    def __init__(
        self,
        workspace: workspace.Workspace,
        url: str,
        namespace: str,
        max_workers=None,
        download_timeout: int = 125,
        logger: logging.Logger | None = None,
    ):
        self.download_timeout = download_timeout
        self.advisories_dir_path = Path(workspace.input_path) / self._cvrf_dir
        self.max_workers = max_workers if isinstance(max_workers, int) else 8
        self.url = url
        self.namespace = namespace
        self.cvrfs = []

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def _fetch_data(self, url) -> requests.Response:
        return http.get(f"{self.url}/{url}", self.logger, stream=True, timeout=self.download_timeout)

    def _download(self):
        """
        Downloads openEuler advisories files
        :return:
        """
        # download cvrf index
        try:
            self.logger.info(f"downloading {self.namespace} advisory index.txt")
            files = self._fetch_data(self._cvrf_index).text.splitlines()
        except Exception:
            self.logger.exception(f"Error downloading {self.namespace} advisories from {self.url}")
            raise
        # download all cvrf file, for example, `2025/cvrf-openEuler-SA-2025-1834.xml`
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._fetch_data, file): file for file in files}
            for future in tqdm(as_completed(futures), total=len(files), desc=f"Downloading {self.namespace} CVRF files"):
                file = futures[future]
                try:
                    data = future.result()
                    if not data:
                        continue
                    # store cvrfs by year
                    year = file.split("/")[0]
                    if not os.path.exists(self.advisories_dir_path / year):
                        os.makedirs(self.advisories_dir_path / year, exist_ok=True)
                    # write into xml files
                    cvrf_file = self.advisories_dir_path / file
                    with open(cvrf_file, "wb") as fp:
                        fp.write(data.content)
                    # record all file sub-directorys
                    self.cvrfs.append(file)
                except Exception as e:
                    self.logger.warning(f"Failed to download {file}: {e}")

    def _parse_cves_from_cvrf(self, cvrf: str):
        cve_record = {}
        tree = ET.parse(self.advisories_dir_path / cvrf)
        root = tree.getroot()
        for vulnerability in root.findall(".//vuln:Vulnerability", NAMESPACES):
            # common info
            vuln_name = vulnerability.find("vuln:CVE", NAMESPACES).text
            vuln_link = vulnerability.find(".//vuln:Remediation/vuln:URL", NAMESPACES).text
            vuln_desc = vulnerability.find('.//vuln:Note[@Title="Vulnerability Description"]', NAMESPACES).text
            vuln_seve = vulnerability.find(".//vuln:Threat/vuln:Description", NAMESPACES).text
            # CVSS
            vuln_cvss = []
            cvss_scores = vulnerability.findall(".//vuln:CVSSScoreSets/vuln:ScoreSet", NAMESPACES)
            for score in cvss_scores:
                base_score = score.find("vuln:BaseScore", NAMESPACES)
                vector = score.find("vuln:Vector", NAMESPACES)
                if base_score is not None and vector is not None:
                    vuln_cvss.append({
                        "Score": float(base_score.text),
                        "Vector": vector.text,
                    })

            # store cves by openEuler releases
            for pkg in root.findall('.//prod:Branch[@Type="Package Arch"][@Name="src"]/prod:FullProductName', NAMESPACES):
                record = copy.deepcopy(vulnerability_element)
                record["Vulnerability"]["Name"] = vuln_name
                record["Vulnerability"]["Link"] = vuln_link
                record["Vulnerability"]["Description"] = vuln_desc
                record["Vulnerability"]["Severity"] = vuln_seve
                record["Vulnerability"]["CVSS"] = vuln_cvss
                
                # Get openEuler version from CPE (e.g., cpe:/a:openEuler:openEuler:22.03-LTS-SP3)
                cpe = pkg.get("CPE")
                if not cpe:
                    continue
                release = cpe.split(":")[-1] # e.g., 22.03-LTS-SP3
                full_namespace = f"{self.namespace}:{release}" # e.g., openeuler: 22.03-LTS-SP3
                record["Vulnerability"]["NamespaceName"] = full_namespace

                # Get fixed package name (e.g., libxkbfile-1.1.0-6.oe2203sp3.src.rpm)
                full_name = pkg.text
                pkg_name = full_name.split("-")[0]
                fixed_version = "-".join(full_name.split("-")[1:]).split(".src")[0] # 1.1.0-6.src
                record["Vulnerability"]["FixedIn"].append({
                    "Name": pkg_name,
                    "Version": fixed_version,
                    "NamespaceName": full_namespace,
                    "VersionFormat": "rpm",
                })
            if "full_namespace" not in cve_record:
                cve_record["full_namespace"] = []
            cve_record["full_namespace"].append(record)
            
        return cve_record

    def _normalize(self) -> dict[str, dict[str, Any]]:
        """
        Parse all cvrf files, record the cev data 
        :param:
        :return:
        """
        cve_dict = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._parse_cves_from_cvrf, cvrf): cvrf for cvrf in self.cvrfs}
            for future in as_completed(futures):
                try:
                    data = future.result()
                    for vuln in data:
                        cve_id = vuln["Vulnerability"]["Name"]
                        if cve_id not in cve_dict:
                            cve_dict[cve_id] = vuln
                        else:
                            cve_dict[cve_id]["Vulnerability"]["FixedIn"].extend(vuln["Vulnerability"]["FixedIn"])
                except Exception as e:
                    self.logger.warning(f"Failed to parse openEuler cvrfs: {e!s}")
        return cve_dict

    def get(self):
        """
        Download, load and normalize openeuler sec db and return a dict of release - list of vulnerability records
        :return:
        """
        # download the data
        self._download()
        yield self._normalize()
