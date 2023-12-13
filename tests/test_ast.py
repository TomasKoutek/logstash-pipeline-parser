import unittest
from ipaddress import IPv4Address
from typing import NoReturn

from logstash_pipeline_parser.tree import AST
from logstash_pipeline_parser.tree import ParseError


class ASTTestCase(unittest.TestCase):

    def setUp(self) -> NoReturn:
        self.ast = AST()
        self.data = r"""
            input {
              syslog {
                host => "127.0.0.1"
                port => 123
                codec => cef
                hashmap => {
                  somekey => "value"
                }
              }
            }
            """

    def test_parse_exception(self) -> NoReturn:
        with self.assertRaises(ParseError) as cm:
            self.ast.parse_config(r"""
                        input # missing left curly bracket
                          syslog {
                            host => "127.0.0.1"
                          }
                        }
                        """)

        self.assertEqual(str(cm.exception), "\n"
                                            "                        input # missing left curly bracket\n"
                                            "                        ^\n"
                                            "ParseException: Expected end of text, found 'input'  (at char 25), (line:2, col:25)\n"
                                            "logstash_pipeline_parser.tree.AST")

    def test_default(self) -> NoReturn:
        self.assertEqual(self.ast.parse_config(self.data), [
            ["input", [
                ["syslog", [
                    ["host", [IPv4Address("127.0.0.1")]],
                    ["port", [123]],
                    ["codec", ["cef"]],
                    ["hashmap", [
                        [
                            ["somekey", ["value"]]
                        ]
                    ]]
                ]]
            ]]
        ])

    def test_custom_func(self) -> NoReturn:
        self.ast.add_type("host", str)
        self.ast.add_type("port", lambda x: x * 2)

        self.assertEqual(self.ast.parse_config(self.data), [
            ["input", [
                ["syslog", [
                    ["host", ["127.0.0.1"]],
                    ["port", [246]],
                    ["codec", ["cef"]],
                    ["hashmap", [
                        [
                            ["somekey", ["value"]]
                        ]
                    ]]
                ]]
            ]]
        ])

    def test_custom_class(self) -> NoReturn:
        class Test:
            def __init__(self, value: str) -> NoReturn:
                self.value = value

            def __eq__(self, other) -> bool:
                return other.value == self.value

        self.ast.add_type("codec", Test)

        parsed = self.ast.parse_config(self.data)
        self.assertIsInstance(parsed[0][1][0][1][2][1][0], Test)
        self.assertEqual(parsed[0][1][0][1][2][1][0], Test("cef"))
