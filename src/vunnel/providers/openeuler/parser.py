from __future__ import annotations

import copy
import logging
import json
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


class Parser:
    _csaf_dir = "csaf"
    _csaf_index = "index.txt"

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
        self.advisories_dir_path = Path(workspace.input_path) / self._csaf_dir
        self.max_workers = max_workers if isinstance(max_workers, int) else 8
        self.url = url
        self.namespace = namespace
        self.csafs = []

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
        # download csaf index
        try:
            self.logger.info(f"downloading {self.namespace} advisory index.txt")
            files = self._fetch_data(self._csaf_index).text.splitlines()
        except Exception:
            self.logger.exception(f"Error downloading {self.namespace} advisories from {self.url}")
            raise
        # download all csaf file, for example, `2025/csaf-openeuler-sa-2024-1650.json`
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._fetch_data, file): file for file in files}
            for future in tqdm(as_completed(futures), total=len(files), desc=f"Downloading {self.namespace} CSAF files"):
                file = futures[future]
                try:
                    data = future.result()
                    if not data:
                        continue
                    # store csafs by year
                    year = file.split("/")[0]
                    if not os.path.exists(self.advisories_dir_path / year):
                        os.makedirs(self.advisories_dir_path / year, exist_ok=True)
                    # write into json files
                    csaf_file = self.advisories_dir_path / file
                    with open(csaf_file, "wb") as fp:
                        fp.write(data.content)
                    # record all stored file paths
                    self.csafs.append(file)
                except Exception as e:
                    self.logger.warning(f"Failed to download {file}: {e}")

    def _get_cve_link(self, references: list, cve_id: str) -> str:
        for ref in references:
            if ref.get("category") == "self" and cve_id == ref.get("summary", ""):
                return ref.get("url", "")
        return ""
            
    def _get_cve_description(self, notes: list) -> str:
        for note in notes:
            if note.get("category") == "description":
                return note.get("text", "")
        return ""

    def _parse_cves_from_csaf(self, csaf: str) -> dict[str, dict[str, Any]]:
        # parse csaf file
        with open(self.advisories_dir_path / csaf, 'r') as f:
            root = json.load(f)    
        references = root.get("document", {}).get("references", [])
        vulns = root.get("vulnerabilities", [])
        if not vulns:
            return {}

        # record all cves
        cve_record = {}
        for vuln in vulns:
            vuln_name = vuln.get("cve")
            vuln_link = self._get_cve_link(references=references, cve_id=vuln_name)
            vuln_desc = self._get_cve_description(notes=vuln.get("notes", []))
            vuln_cvss = []
            vuln_seve = ""
            cvss = vuln.get("scores", [])[0].get("cvss_v3", {})
            if cvss:
                vuln_seve = cvss.get("baseSeverity")
                vuln_cvss.append({
                    "base_metrics": {
                        "base_score": cvss.get("baseScore"),
                        "base_severity": cvss.get("baseSeverity"),
                        "exploitability_score": "N/A",  # Not available in CSAF
                        "impact_score": "N/A",  # Not available in CSAF
                    },
                    "status": "N/A", # Not available in CSAF
                    "vector_string": cvss.get("vectorString"),
                    "version": cvss.get("version"),
                })

            # store cves by openEuler releases
            for pkg in vuln.get("product_status")["fixed"]:
                if not pkg.endswith(".src"):
                    continue
                record = copy.deepcopy(vulnerability_element)
                record["Vulnerability"]["Name"] = vuln_name
                record["Vulnerability"]["Link"] = vuln_link
                record["Vulnerability"]["Description"] = vuln_desc
                record["Vulnerability"]["Severity"] = vuln_seve
                record["Vulnerability"]["CVSS"] = vuln_cvss
                
                # Get openEuler version from fixed product (e.g., "openEuler-22.03-LTS-SP3:kernel-5.10.0-200.0.0.113.oe2203sp3.src")
                os_full_name = pkg.split(":")[0]
                release = os_full_name.split("-", maxsplit=1)[-1] # e.g., 22.03-LTS-SP3
                full_namespace = f"{self.namespace}:{release}" # e.g., openeuler:22.03-LTS-SP3
                record["Vulnerability"]["NamespaceName"] = full_namespace

                # Get fixed package name (e.g., kernel-5.10.0-200.0.0.113.oe2203sp3.src)
                full_fixed_name = pkg.split(":")[1]
                pkg_parts = full_fixed_name.split("-", maxsplit=1)
                fixed_version = pkg_parts[1].split(".src")[0] # 5.10.0-200.0.0.113.oe2203sp3
                record["Vulnerability"]["FixedIn"].append({
                    "Name": pkg_parts[0], # e.g., kernel
                    "Version": fixed_version,
                    "NamespaceName": full_namespace,
                    "VersionFormat": "rpm",
                })
                if (namespace := cve_record.setdefault(full_namespace, {})) and (existing_record := namespace.get(vuln_name)):
                    existing_record["Vulnerability"]["FixedIn"].extend(record["Vulnerability"]["FixedIn"])
                else:
                    namespace[vuln_name] = record
            
        return cve_record

    def get(self):
        # download the csaf files
        self._download()
        
        # parse all csaf files, record the cve data 
        cve_dict = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._parse_cves_from_csaf, csaf): csaf for csaf in self.csafs}
            for future in as_completed(futures):
                try:
                    data = future.result()
                    for namespace, vuln_dict in data.items():
                        for cve_id, vuln in vuln_dict.items():
                            if (ns_record := cve_dict.setdefault(namespace, {})) and (existing_record := ns_record.get(cve_id)):
                                existing_record["Vulnerability"]["FixedIn"].extend(vuln["Vulnerability"]["FixedIn"])
                            else:
                                ns_record[cve_id] = vuln
                except Exception as e:
                    self.logger.warning(f"Failed to parse openEuler csafs: {e}")
        
        for namespace, vuln_dict in cve_dict.items():
            yield namespace, vuln_dict
