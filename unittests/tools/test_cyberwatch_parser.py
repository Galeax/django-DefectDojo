import unittest
from dojo.models import Test
from dojo.tools.cyberwatch.parser import CyberwatchParser
from pathlib import Path


class TestCyberwatchParser(unittest.TestCase):

    def setUp(self):
        self.parser = CyberwatchParser()
        self.test = Test()

    def test_no_findings(self):
        testfile = Path("unittests/scans/cyberwatch/no_findings.json")
        with testfile.open('rb') as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(0, len(findings))

    def test_one_security_issue(self):
        testfile = Path("unittests/scans/cyberwatch/one_security_issue.json")
        with testfile.open('rb') as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual("Security Issue - Content Security Policy", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertIn("Host-X", [e.host for e in finding.unsaved_endpoints])
            self.assertIn("Host-Y", [e.host for e in finding.unsaved_endpoints])
            self.assertEqual("No mitigation provided.", finding.mitigation)
            self.assertEqual("", finding.references)
                        
            
    def test_one_cve(self):
        testfile = Path("unittests/scans/cyberwatch/one_cve.json")
        with testfile.open('rb') as file:
            findings = self.parser.get_findings(file, self.test)
            self.assertEqual(1, len(findings))

            finding = findings[0]
            self.assertEqual("CVE-2020-15677 on firefox", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertIn("CVE Score: 6.1", finding.description)
            self.assertIn("CVE Published At: 2020-10-01T19:15:13.830+02:00", finding.description)
            self.assertIn("Exploit Code Maturity: unproven", finding.description)
            self.assertIn("EPSS: 0.00349", finding.description)
            self.assertEqual("No mitigation provided.", finding.mitigation)
            self.assertEqual("CWE ID: CWE-601\n", finding.impact)
            self.assertEqual("Updated At: 2022-11-16T15:15:40.607+01:00", finding.references)
            self.assertEqual(4, len(finding.unsaved_endpoints))
            endpoint_hosts = [e.host for e in finding.unsaved_endpoints]
            self.assertIn("Host-A", endpoint_hosts)
            self.assertIn("Host-B", endpoint_hosts)
            self.assertIn("Host-C", endpoint_hosts)
            self.assertIn("Host-D", endpoint_hosts)

    def test_mixed_findings(self):
        testfile = Path("unittests/scans/cyberwatch/mixed_findings.json")
        with testfile.open('rb') as file:
            findings = self.parser.get_findings(file, self.test)

            self.assertEqual(7, len(findings))

            security_issues = [f for f in findings if "Security Issue" in f.title or "securityIssue" in f.title or f.title.startswith("test_securityIssue")]
            cves = [f for f in findings if "CVE-" in f.title]

            self.assertEqual(4, len(cves))
            self.assertEqual(3, len(security_issues))
            
            cve_map = {f.title.split(" ")[0]: f for f in cves}
            self.assertIn("CVE-2020-17020", cve_map)
            self.assertIn("CVE-2020-17062", cve_map)
            self.assertIn("CVE-2020-17063", cve_map)
            self.assertIn("CVE-2020-17064", cve_map)

            self.assertEqual("Low", cve_map["CVE-2020-17020"].severity)
            self.assertEqual("High", cve_map["CVE-2020-17062"].severity)
            self.assertEqual("Medium", cve_map["CVE-2020-17063"].severity)
            self.assertEqual("High", cve_map["CVE-2020-17064"].severity)

            for cve_finding in cves:
                self.assertTrue(len(cve_finding.unsaved_endpoints) > 0)
                self.assertIsNotNone(cve_finding.component_name)


            si_map = {f.title: f for f in security_issues}
            self.assertIn("Security Issue - X-Frame-Options header", si_map)
            self.assertIn("Security Issue - X-Content-Type-Options header", si_map)
            self.assertIn("Security Issue - test_securityIssue_Cve", si_map)

            self.assertEqual("Low", si_map["Security Issue - X-Frame-Options header"].severity)
            self.assertEqual("Low", si_map["Security Issue - X-Content-Type-Options header"].severity)
            self.assertEqual("Info", si_map["Security Issue - test_securityIssue_Cve"].severity)

            xframe_endpoints = [e.host for e in si_map["Security Issue - X-Frame-Options header"].unsaved_endpoints]
            self.assertIn("Host-Z", xframe_endpoints)
            self.assertIn("Host-Q", xframe_endpoints)

            xcontent_endpoints = [e.host for e in si_map["Security Issue - X-Content-Type-Options header"].unsaved_endpoints]
            self.assertIn("Host-Z", xcontent_endpoints)
            self.assertIn("Host-Q", xcontent_endpoints)

            test_si_cve_endpoints = [e.host for e in si_map["Security Issue - test_securityIssue_Cve"].unsaved_endpoints]
            self.assertIn("Host-R", test_si_cve_endpoints)

            self.assertIn("CVE-2024-7025", si_map["Security Issue - test_securityIssue_Cve"].unsaved_vulnerability_ids)

            for i, finding in enumerate(findings):
                with self.subTest(i=i):
                    self.assertIsNotNone(finding.title)
                    self.assertIn(finding.severity, ["Critical", "High", "Medium", "Low", "Info"])
                    self.assertIsNotNone(finding.description)
                    self.assertIsNotNone(finding.mitigation)
                    self.assertIsNotNone(finding.impact)
                    self.assertIsNotNone(finding.references)
                    self.assertTrue(len(finding.unsaved_endpoints) > 0)
