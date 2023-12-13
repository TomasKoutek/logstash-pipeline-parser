import unittest
from ipaddress import IPv4Address
from ipaddress import IPv6Address
from typing import NoReturn
from pathlib import Path

from logstash_pipeline_parser import Pipeline


class PipelineTestCase(unittest.TestCase):

    def test_parse(self) -> NoReturn:
        pipeline = Pipeline(r"""
            input {
              syslog {
                host => "127.0.0.1"
                port => 123
                codec => cef
                qhashmap => {
                  somekey => "vaur"
                }
                ssl_key => "/some/path/to/key"
              }
            }
              """)

        self.assertEqual(pipeline.parse(), [
            ["input", [
                ["syslog", [
                    ["host", [IPv4Address("127.0.0.1")]],
                    ["port", [123]],
                    ["codec", ["cef"]],
                    ["qhashmap", [
                        [
                            ["somekey", ["vaur"]]
                        ]
                    ]],
                    ["ssl_key", [
                        Path("/some/path/to/key")
                    ]]
                ]]
            ]]
        ])

    def test_matcher(self) -> NoReturn:
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["input", "syslog", "port"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["*", "syslog", "port"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["input", "*", "port"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["input", "syslog", "*"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "udp", "port"], ["input", "*", "port"]))
        self.assertTrue(Pipeline._matcher(["input", "syslog", "port"], ["*"]))

    def test_search(self) -> NoReturn:
        data = r"""
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
                  public_key => "/test/file.txt"
                }
              }
            }
            """

        pipeline = Pipeline(data)

        self.assertEqual(
            list(pipeline.search("input.syslog.port")),
            [("input.syslog.port", [123])]
        )

        self.assertEqual(
            list(pipeline.search("input.*.port")),
            [("input.syslog.port", [123]), ("input.udp.sub.port", [456])]
        )

        self.assertEqual(
            list(pipeline.search("*.port")),
            [("input.syslog.port", [123]), ("input.udp.sub.port", [456]), ("filter.plug.port", [789])]
        )

        self.assertEqual(
            list(pipeline.search("*.name_1")),
            [("filter.if.plugin1.name_1", [42]), ("filter.else if.plugin2.name_1", [42]), ("filter.else.plugin3.name_1", [42])]
        )

        self.assertEqual(
            list(pipeline.search("filter.plug.somearr")),
            [("filter.plug.somearr", [["abc", "def"]])]
        )

        self.assertEqual(
            list(pipeline.search("input.udp")),
            [("input.udp", [["sub", [[["port", [456]], ["host", [IPv6Address("::1")]]]]]])]
        )

        self.assertEqual(
            list(pipeline.search("*.plugin3.public_key")), [("filter.else.plugin3.public_key", [Path("/test/file.txt")])]
        )

    def test_from_file(self) -> NoReturn:
        self.assertEqual(Pipeline.from_file("./test_pipeline.conf").parse(), [
            ["input", [
                ["syslog", [
                    ["port", [12345]],
                    ["codec", ["cef"]],
                    ["syslog_field", ["syslog"]]
                ]]
            ]]
        ])

        self.assertEqual(Pipeline.from_file(Path("./test_pipeline.conf")).parse(), [
            ["input", [
                ["syslog", [
                    ["port", [12345]],
                    ["codec", ["cef"]],
                    ["syslog_field", ["syslog"]]
                ]]
            ]]
        ])


if __name__ == "__main__":
    unittest.main()
