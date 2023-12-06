import unittest
from ipaddress import IPv4Address
from ipaddress import IPv6Address
from typing import NoReturn

from logstash_pipeline_parser import Pipeline


class PipelineTestCase(unittest.TestCase):

    def setUp(self) -> NoReturn:
        self.ppl = Pipeline()

    def test_parse(self) -> NoReturn:
        self.assertEqual(self.ppl.parse("""
            input {
              syslog {
                host => "127.0.0.1"
                port => 123
                codec => cef
                qhashmap => {
                  somekey => "vaur"
                }
              }
            }
              """), [["input", [["syslog", [["host", IPv4Address("127.0.0.1")], ["port", 123], ["codec", "cef"], ["qhashmap", [["somekey", "vaur"]]]]]]]])

    def test_matcher(self) -> NoReturn:
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["input", "syslog", "port"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["*", "syslog", "port"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["input", "*", "port"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["input", "syslog", "*"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "udp", "port"], ["input", "*", "port"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["*"]))

    def test_search(self) -> NoReturn:
        data = """
            input {
              syslog {
                port => 123
                codec => cef
                some_key => {
                  somekey => "value"
                }
              }

              udp {
                sub => {
                  port => 456
                  host => "::1"
                }
              }
            }

            filter {
              plug {
                port => 789 # comment
                somearr => ["abc", "def"]
              }
                # comment
              if [se][lec][tor] == "192.168.0.1" {
                plugin1 {
                  name_1 => 42
                }
              }
              else if 1 < 2 {
                plugin2 {
                  name_1 => 42
                }
              }
              # some comment
              else {
                plugin3 {
                  name_1 => 42
                }
              }
            }
            """

        with self.assertRaises(ValueError):
            list(self.ppl.search("some.key.*", data))

        self.assertEqual(
            list(self.ppl.search("input.syslog.port", data)),
            [("input.syslog.port", 123)]
        )

        self.assertEqual(
            list(self.ppl.search("input.*.port", data)),
            [("input.syslog.port", 123), ("input.udp.sub.port", 456)]
        )

        self.assertEqual(
            list(self.ppl.search("*.port", data)),
            [("input.syslog.port", 123), ("input.udp.sub.port", 456), ("filter.plug.port", 789)]
        )

        self.assertEqual(
            list(self.ppl.search("*.name_1", data)),
            [("filter.if.plugin1.name_1", 42), ("filter.else if.plugin2.name_1", 42), ("filter.else.plugin3.name_1", 42)]
        )

        self.assertEqual(
            list(self.ppl.search("filter.plug.somearr", data)),
            [("filter.plug.somearr", ["abc", "def"])]
        )

        self.assertEqual(
            list(self.ppl.search("input.udp", data)),
            [("input.udp", [["sub", [["port", 456], ["host", IPv6Address("::1")]]]])]
        )


if __name__ == "__main__":
    unittest.main()
