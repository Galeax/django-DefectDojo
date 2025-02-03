import json
import logging
from datetime import datetime
from pathlib import Path

from cvss.cvss3 import CVSS3
import cvss.parser

from dojo.models import Finding, Endpoint, Endpoint_Status

logger = logging.getLogger(__name__)

class CyberwatchParser:
    def get_scan_types(self):
        return ["Cyberwatch scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Cyberwatch scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import Cyberwatch scan results in JSON format."

    def get_findings(self, filename, test):
        """
        Main entry point. Reads the file line by line, processes CVEs and security issues:
        - Accumulates CVE data for all lines first.
        - Processes security issues directly as they are independent.
        - After processing all lines, builds findings for CVEs and combines them with security issue findings.
        - Applies a global version deduplication step at the end.
        """
        logger.debug(f"Starting get_findings with filename: {filename}")
        try:
            file_content = self.read_file_content(filename)
            lines = file_content.splitlines()

            cve_data = {}
            security_issue_findings = []

            # Process each line
            for line in lines:
                if not line.strip():
                    continue
                json_data = self.safe_parse_json(line)
                if not json_data:
                    continue

                entry_type = json_data.get("type", "").lower()
                if entry_type == "cve":
                    self.collect_cve_data(json_data, cve_data)
                elif entry_type == "security issue":
                    si_finding = self.process_security_issue(json_data, test)
                    if si_finding:
                        security_issue_findings.append(si_finding)
                else:
                    logger.error(f"Unknown type '{json_data.get('type')}' in JSON line.")

            # Build CVE findings after accumulating all data
            cve_findings = []
            for cve_code, c_data in cve_data.items():
                cve_findings.extend(self.build_findings_for_cve(cve_code, c_data, test))

            # Combine all findings
            all_findings = cve_findings + security_issue_findings

            # Deduplicate versions globally
            self.global_version_dedup(all_findings)

            return all_findings
        except Exception as e:
            logger.error(f"Error processing file: {e}")
            return []

    def read_file_content(self, filename):
        """Reads file content either from a file-like object or a file path."""
        if hasattr(filename, "read"):
            return filename.read()
        else:
            with open(filename, 'r', encoding='utf-8') as f:
                return f.read()

    def safe_parse_json(self, line):
        """Safely parse a single line of JSON, logging and skipping invalid lines."""
        if not line.strip():
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON line: {e}")
            return None

    def collect_cve_data(self, json_data, cve_data):
        """
        Accumulates CVE data across multiple lines.
        If updates_assets are present, associate products, endpoints, and versions.
        If no updates_assets, store endpoints in no_product_endpoints.
        """
        cve_code = json_data.get("cve_code")
        if not cve_code:
            logger.warning("No cve_code found, skipping line.")
            return

        # Extract and parse top-level CVE fields
        cve_score = json_data.get("cve_score", "N/A")
        cve_published_at = json_data.get("cve_published_at", "N/A")
        exploit_code_maturity = json_data.get("exploit_code_maturity", "N/A")
        updated_at_str = json_data.get("updated_at", "N/A")
        cve_epss = json_data.get("cve_epss", "N/A")
        cvss_v3_vector = json_data.get("cvss_v3")

        updated_at = self.parse_datetime(updated_at_str)
        cvssv3, cvssv3_score, severity = self.parse_cvss(cvss_v3_vector, json_data)

        description = (
            f"CVE Score: {cve_score}\n"
            f"CVE Published At: {cve_published_at}\n"
            f"Exploit Code Maturity: {exploit_code_maturity}\n"
            f"EPSS: {cve_epss}\n"
        )

        cwes = json_data.get("cwes", {})
        if not isinstance(cwes, dict):
            logger.error(f"Invalid 'cwes' data: {cwes}")
            cwes = {}
        cwe_id = cwes.get("cwe_id")
        cwe_num = self.extract_cwe_num(cwe_id)

        impact = f"CWE ID: {cwe_id or 'N/A'}\n"
        references = f"Updated At: {updated_at_str}"

        # Initialize CVE data if not present
        if cve_code not in cve_data:
            cve_data[cve_code] = {
                "cwe_num": cwe_num,
                "epss": cve_epss if cve_epss != "N/A" else None,
                "severity": severity,
                "description": description,
                "impact": impact,
                "references": references,
                "cvssv3": cvssv3,
                "cvssv3_score": cvssv3_score,
                "products": {},
                "no_product_endpoints": set()
            }

        c_data = cve_data[cve_code]
        # Update CVE-level info if needed
        c_data["cwe_num"] = c_data["cwe_num"] or cwe_num
        if cve_epss != "N/A":
            c_data["epss"] = cve_epss
        c_data["severity"] = severity
        c_data["description"] = description
        c_data["impact"] = impact
        c_data["references"] = references
        c_data["cvssv3"] = cvssv3
        c_data["cvssv3_score"] = cvssv3_score

        # Handle servers and updates_assets
        servers = json_data.get("servers", [])
        if not isinstance(servers, list):
            logger.error(f"'servers' is not a list: {servers}")
            return
        server_lookup = {s.get("computer_name", ""): s for s in servers if isinstance(s, dict)}

        updates_assets = json_data.get("updates_assets", {})

        if updates_assets:
            self.collect_products_data(updates_assets, server_lookup, c_data)
        else:
            # No products - just gather endpoints
            for server_name in server_lookup.keys():
                c_data["no_product_endpoints"].add(server_name)

    def collect_products_data(self, updates_assets, server_lookup, c_data):
        """
        Given updates_assets and a server lookup, populate product data with endpoints, versions, and mitigation info.
        """
        for product, data in updates_assets.items():
            assets_list = data.get("assets", [])
            versions_list = data.get("versions", [])

            if product not in c_data["products"]:
                c_data["products"][product] = {
                    "endpoints": set(),
                    "versions": set(),
                    "active_mitigated_data": []
                }

            p_data = c_data["products"][product]
            for v in versions_list:
                p_data["versions"].add(v)

            mitigated_dates = []
            active_status = False
            for asset in assets_list:
                server_data = server_lookup.get(asset)
                if not server_data:
                    continue
                server_active_status = server_data.get("active", False)
                fixed_at_str = server_data.get("fixed_at")

                if server_active_status:
                    active_status = True
                else:
                    mitigated_date = self.parse_fixed_at(fixed_at_str)
                    mitigated_dates.append(mitigated_date)

                p_data["endpoints"].add(asset)

            # Determine overall mitigated_date for this product in this line
            mitigated_date = None if active_status else (max(mitigated_dates) if mitigated_dates else None)
            p_data["active_mitigated_data"].append((active_status, mitigated_date))

    def build_findings_for_cve(self, cve_code, c_data, test):
        """
        Builds findings for a single CVE:
        - If no products, create one mitigated finding with no_product_endpoints.
        - Otherwise, one finding per product.
        """
        findings = []
        cwe_num = c_data["cwe_num"]
        epss = c_data["epss"]
        severity = c_data["severity"]
        description = c_data["description"]
        impact = c_data["impact"]
        references = c_data["references"]
        cvssv3 = c_data["cvssv3"]
        cvssv3_score = c_data["cvssv3_score"]
        products = c_data["products"]

        if not products:
            # No products: create a mitigated finding with the CVE code as title
            mitigated_date = datetime.now()
            mitigation = f"Fixed At: {mitigated_date}"
            endpoints = [Endpoint(host=e) for e in c_data["no_product_endpoints"]]

            findings.append(
                self.create_finding(
                    title=cve_code,
                    test=test,
                    description=description,
                    severity=severity,
                    mitigation=mitigation,
                    impact=impact,
                    references=references,
                    active=False,
                    mitigated=mitigated_date,
                    cvssv3=cvssv3,
                    cvssv3_score=cvssv3_score,
                    endpoints=endpoints,
                    cwe_num=cwe_num,
                    epss=epss,
                    cve_code=cve_code
                )
            )
            return findings

        # Normal case: one finding per product
        for product, p_data in products.items():
            component_version_str, active_status, mitigated_date = self.determine_product_finding_state(p_data)
            mitigation = "No mitigation provided."
            if mitigated_date and not active_status:
                mitigation = f"Fixed At: {mitigated_date}"

            endpoints = [Endpoint(host=e) for e in p_data["endpoints"]]

            findings.append(
                self.create_finding(
                    title=f"{cve_code} on {product}",
                    test=test,
                    description=description,
                    severity=severity,
                    mitigation=mitigation,
                    impact=impact,
                    references=references,
                    active=active_status,
                    mitigated=mitigated_date,
                    cvssv3=cvssv3,
                    cvssv3_score=cvssv3_score,
                    endpoints=endpoints,
                    cwe_num=cwe_num,
                    epss=epss,
                    cve_code=cve_code,
                    component_name=product,
                    component_version=component_version_str
                )
            )

        return findings

    def determine_product_finding_state(self, p_data):
        """
        Given product data (endpoints, versions, active_mitigated_data), determine:
        - component_version_str
        - active_status
        - mitigated_date
        """
        unique_versions = sorted(p_data["versions"])
        component_version_str = ", ".join(unique_versions) if unique_versions else "N/A"

        active_status = any(am[0] for am in p_data["active_mitigated_data"])
        if not active_status:
            mitigated_dates = [am[1] for am in p_data["active_mitigated_data"] if am[1]]
            mitigated_date = max(mitigated_dates) if mitigated_dates else None
        else:
            mitigated_date = None

        return component_version_str, active_status, mitigated_date

    def create_finding(self, title, test, description, severity, mitigation, impact, references,
                       active, mitigated, cvssv3, cvssv3_score, endpoints,
                       cwe_num=None, epss=None, cve_code=None, component_name=None, component_version=None):
        """
        Helper to create a Finding object with all the common attributes.
        """
        finding = Finding(
            title=title,
            test=test,
            description=description,
            severity=severity,
            mitigation=mitigation,
            impact=impact,
            references=references,
            active=active,
            verified=False,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated=mitigated,
            numerical_severity=Finding.get_numerical_severity(severity),
            cvssv3=cvssv3,
            cvssv3_score=cvssv3_score,
            static_finding=False,
            dynamic_finding=True,
            component_name=component_name,
            component_version=component_version
        )

        finding.unsaved_endpoints = endpoints

        if cve_code:
            finding.unsaved_vulnerability_ids = [cve_code]
        if cwe_num:
            finding.cwe = cwe_num
        if epss:
            finding.epss_score = epss

        return finding

    def global_version_dedup(self, findings):
        """
        Deduplicate (product, version) pairs across all findings.
        """

        # Assign each finding a "before_sort" index so we can restore original order.
        for idx, f in enumerate(findings):
            f._original_index = idx

        severity_priority_map = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Info': 0
        }
        def severity_priority(sev):
            return severity_priority_map.get(sev, 0)

        findings.sort(key=lambda f: severity_priority(f.severity), reverse=True)

        # Track used versions by product name across ALL severities
        used_versions = {} 

        for f in findings:
            product = getattr(f, "component_name", None)
            if not product:
                continue

            component_version = getattr(f, "component_version", None)
            if not component_version or component_version == "N/A":
                continue

            product_lower = product.lower()

            # Initialize if not present
            if product_lower not in used_versions:
                used_versions[product_lower] = set()

            # For each version in the comma-separated string, remove from the final if previously used
            versions_list = [v.strip() for v in component_version.split(",") if v.strip()]

            unique_versions = []
            for ver in versions_list:
                if ver not in used_versions[product_lower]:
                    unique_versions.append(ver)
                    used_versions[product_lower].add(ver)

            if unique_versions:
                f.component_version = ", ".join(unique_versions)
            else:
                # All were duplicates, so set to None
                f.component_version = None

        # Sort findings back to original order
        findings.sort(key=lambda f: f._original_index)

        # Clean up the temporary index attribute
        for f in findings:
            del f._original_index

    def process_security_issue(self, json_data, test):
        """
        Process a single security issue line, returning one Finding.
        """
        if not json_data:
            logger.error("json_data is None or empty")
            return None

        issue_id = json_data.get("id")
        security_issue_title = json_data.get("security_issue_title", "No Title")
        description = json_data.get("security_issue_description", "")
        severity = self.convert_severity(json_data.get("level", "Info"))
        mitigation = "No mitigation provided."        
        cve_announcements = json_data.get("cve_announcements", [])
        references = "CVE Announcements:\n" + "\n".join(cve_announcements) if cve_announcements else ""

        servers = json_data.get("servers", [])
        if not isinstance(servers, list):
            logger.error(f"'servers' is not a list: {servers}")
            return None

        unsaved_endpoints, unsaved_endpoint_status, active_status, mitigated_date = self.process_servers_for_security_issue(servers)

        if mitigated_date:
            mitigation = f"Mitigated At: {mitigated_date}"

        impact = ""

        finding = Finding(
            title=f"Security Issue - {security_issue_title}",
            test=test,
            description=description,
            severity=severity,
            mitigation=mitigation,
            impact=impact,
            references=references,
            active=active_status,
            verified=False,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated=mitigated_date,
            numerical_severity=Finding.get_numerical_severity(severity),
            static_finding=False,
            dynamic_finding=True,
        )

        if issue_id:
            finding.unique_id_from_tool = str(issue_id)

        if cve_announcements:
            finding.unsaved_vulnerability_ids = cve_announcements
                
        finding.unsaved_endpoints = unsaved_endpoints
        for endpoint_status in unsaved_endpoint_status:
            endpoint_status.finding = finding
        finding.unsaved_endpoint_status = unsaved_endpoint_status

        return finding

    def process_servers_for_security_issue(self, servers):
        """
        Process servers for a security issue, determining active/mitigated status and creating Endpoint_Status objects.
        """
        unsaved_endpoints = []
        unsaved_endpoint_status = []
        active_status = False
        mitigated_dates = []

        for server in servers:
            if not server or not isinstance(server, dict):
                logger.error(f"Invalid server data: {server}")
                continue

            computer_name = server.get("computer_name", "Unknown Hostname")
            endpoint = Endpoint(host=computer_name)
            unsaved_endpoints.append(endpoint)

            server_active_value = server.get("active")
            server_active_status = (server_active_value == "active")

            if server_active_status:
                active_status = True
                mitigated_date = None
            else:
                mitigated_date = datetime.now()
                mitigated_dates.append(mitigated_date)

            detected_at_str = server.get("detected_at")
            detected_at = self.parse_detected_at(detected_at_str)

            endpoint_status = Endpoint_Status(
                endpoint=endpoint,
                finding=None,
                mitigated=mitigated_date,
                last_modified=detected_at,
                false_positive=False,
                out_of_scope=False,
                mitigated_by=None,
            )
            unsaved_endpoint_status.append(endpoint_status)

        # Determine overall mitigated_date for the security issue
        if not active_status:
            mitigated_date = max(mitigated_dates) if mitigated_dates else datetime.now()
        else:
            mitigated_date = None

        return unsaved_endpoints, unsaved_endpoint_status, active_status, mitigated_date

    def parse_detected_at(self, detected_at_str):
        """Parse the detected_at field for a security issue server."""
        try:
            return datetime.strptime(detected_at_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        except (ValueError, TypeError):
            return datetime.now()

    def parse_fixed_at(self, fixed_at_str):
        """Parse fixed_at datetime, defaulting to now if parsing fails."""
        if fixed_at_str:
            try:
                return datetime.strptime(fixed_at_str, '%Y-%m-%dT%H:%M:%S.%f%z')
            except ValueError as e:
                logger.error(f"Error parsing fixed_at date '{fixed_at_str}': {e}")
        return datetime.now()

    def parse_datetime(self, dt_str):
        """Parse a datetime string with fallback to now on error."""
        if dt_str:
            try:
                return datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S.%f%z')
            except (ValueError, TypeError):
                logger.error(f"Error parsing datetime '{dt_str}'")
        return datetime.now()

    def parse_cvss(self, cvss_v3_vector, json_data):
        """
        Parse CVSS v3 vector. If invalid or missing, fallback to severity based on cve_level.
        Returns cvssv3, cvssv3_score, severity.
        """
        if cvss_v3_vector:
            vectors = cvss.parser.parse_cvss_from_text(cvss_v3_vector)
            if vectors and isinstance(vectors[0], CVSS3):
                cvssv3 = vectors[0].clean_vector()
                cvssv3_score = vectors[0].scores()[0]
                severity = vectors[0].severities()[0]
                return cvssv3, cvssv3_score, severity
            else:
                logger.error(f"Invalid CVSS v3 vector: {cvss_v3_vector}")
        # Fall back
        severity = self.convert_severity(json_data.get("cve_level", "Info"))
        return None, None, severity

    def extract_cwe_num(self, cwe_id):
        """Extract numerical CWE from a CWE-ID string."""
        if cwe_id and cwe_id.startswith("CWE-"):
            try:
                return int(cwe_id.replace("CWE-", ""))
            except ValueError:
                logger.error(f"Invalid CWE ID format: {cwe_id}")
        return None

    def convert_severity(self, severity):
        severity_mapping = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Info",
            "LEVEL_CRITICAL": "Critical",
            "LEVEL_HIGH": "High",
            "LEVEL_MEDIUM": "Medium",
            "LEVEL_LOW": "Low",
            "LEVEL_INFO": "Info",
        }
        return severity_mapping.get(severity.upper(), "Info")
