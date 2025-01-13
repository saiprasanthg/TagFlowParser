import unittest
from unittest.mock import patch, mock_open
from io import StringIO
from main import parse_lookup_table, load_protocols, parse_flow_logs, map_tags_and_generate_output, write_output

class TestFlowLogParser(unittest.TestCase):

    def setUp(self):
        self.lookup_data = """dstport,protocol,tag
80,tcp,HTTP
443,tcp,HTTPS
53,udp,DNS
"""

        self.protocol_data = """number,name
6,tcp
17,udp
1,icmp
"""

        self.flow_log_data = """2 123 eni-0ab 192.168.1.1 10.0.0.1 12345 80 6 1000 2000 1620140761 1620140821 ACCEPT OK
2 123 eni-0ab 192.168.1.2 10.0.0.2 54321 443 6 1500 3000 1620140761 1620140821 ACCEPT OK
2 123 eni-0ab 192.168.1.3 10.0.0.3 56789 53 17 500 1000 1620140761 1620140821 ACCEPT OK
"""

    @patch("builtins.open", new_callable=mock_open, read_data="dstport,protocol,tag\n80,tcp,http\n443,tcp,https\n53,udp,dns")
    def test_parse_lookup_table(self, mock_file):
        lookup = parse_lookup_table("dummy_lookup.csv")
        expected_lookup = {
            ("80", "tcp"): ["http"],
            ("443", "tcp"): ["https"],
            ("53", "udp"): ["dns"]
        }
        self.assertEqual(lookup, expected_lookup)

    @patch("builtins.open", new_callable=mock_open, read_data="number,name\n6,tcp\n17,udp\n1,icmp")
    def test_load_protocols(self, mock_file):
        protocols = load_protocols("protocols.csv")
        expected_protocols = {
            "6": "tcp",
            "17": "udp",
            "1": "icmp"
        }
        self.assertEqual(protocols, expected_protocols)


    def test_map_tags_and_generate_output(self):
        lookup = {
            ("80", "tcp"): ["http"],
            ("443", "tcp"): ["https"],
            ("53", "udp"): ["dns"]
        }
        logs = [
            ("80", "tcp"),
            ("443", "tcp"),
            ("53", "udp"),
            ("8080", "tcp")
        ]
        tag_output, port_protocol_output, untagged_count = map_tags_and_generate_output(logs, lookup)
        expected_tag_output = [
            ("dns", 1),
            ("http", 1),
            ("https", 1)
        ]
        expected_port_protocol_output = [
            ("53", "udp", 1),
            ("80", "tcp", 1),
            ("443", "tcp", 1),
            ("8080", "tcp", 1)
        ]
        self.assertEqual(sorted(tag_output), sorted(expected_tag_output))
        self.assertEqual(sorted(port_protocol_output), sorted(expected_port_protocol_output))
        self.assertEqual(untagged_count, 1)

    @patch("builtins.open", new_callable=mock_open)
    def test_write_output(self, mock_file):
        tag_output = [
            ("http", 1),
            ("https", 2),
            ("dns", 1)
        ]
        port_protocol_output = [
            ("80", "tcp", 1),
            ("443", "tcp", 2),
            ("53", "udp", 1)
        ]
        untagged_count = 1

        write_output(tag_output, port_protocol_output, untagged_count, "output.csv")

        mock_file().write.assert_any_call("Tag Counts:\n")
        mock_file().write.assert_any_call("Tag,Count\n")
        mock_file().write.assert_any_call("http,1\n")
        mock_file().write.assert_any_call("https,2\n")
        mock_file().write.assert_any_call("dns,1\n")
        mock_file().write.assert_any_call("Untagged,1\n\n")
        mock_file().write.assert_any_call("Port/Protocol Combination Counts:\n")
        mock_file().write.assert_any_call("Port,Protocol,Count\n")
        mock_file().write.assert_any_call("80,tcp,1\n")
        mock_file().write.assert_any_call("443,tcp,2\n")
        mock_file().write.assert_any_call("53,udp,1\n")

if __name__ == "__main__":
    unittest.main()
