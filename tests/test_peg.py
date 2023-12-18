import unittest
from ipaddress import IPv4Address
from ipaddress import IPv6Address
from typing import NoReturn

from pyparsing import pyparsing_test as ppt

from logstash_pipeline_parser.tree import PEG


class PEGTestCase(ppt.TestParseResultsAsserts, unittest.TestCase):

    def test_comment(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.comment, "# comment", ["# comment"])

    def test_double_quoted_string(self) -> NoReturn:
        # grok { match => { "message" => " ... \"%{GREEDYDATA:data}\"" }
        self.assertParseAndCheckList(PEG.double_quoted_string, r'"st\"ring\""', ['st"ring"'])
        self.assertParseAndCheckList(PEG.double_quoted_string, r'"string"', ["string"])

    def test_single_quoted_string(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.single_quoted_string, r"'st\'ring\''", ["st'ring'"])
        self.assertParseAndCheckList(PEG.single_quoted_string, "'string'", ["string"])

    def test_compare_operator(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.compare_operator, "==", ["=="])
        self.assertParseAndCheckList(PEG.compare_operator, "!=", ["!="])
        self.assertParseAndCheckList(PEG.compare_operator, "<=", ["<="])
        self.assertParseAndCheckList(PEG.compare_operator, ">=", [">="])
        self.assertParseAndCheckList(PEG.compare_operator, "<", ["<"])
        self.assertParseAndCheckList(PEG.compare_operator, ">", [">"])

    def test_boolean_operator(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.boolean_operator, "and", ["and"])
        self.assertParseAndCheckList(PEG.boolean_operator, "or", ["or"])
        self.assertParseAndCheckList(PEG.boolean_operator, "xor", ["xor"])
        self.assertParseAndCheckList(PEG.boolean_operator, "nand", ["nand"])

    def test_regexp_operator(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.regexp_operator, "=~", ["=~"])
        self.assertParseAndCheckList(PEG.regexp_operator, "!~", ["!~"])

    def test_in_operator(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.in_operator, "in", ["in"])

    def test_not_in_operator(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.not_in_operator, "not in", ["not", "in"])
        self.assertParseAndCheckList(PEG.not_in_operator, "not     in", ["not", "in"])
        self.assertParseAndCheckList(PEG.not_in_operator, "not\tin", ["not", "in"])

    def test_string(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.string, "'string'", ["string"])
        self.assertParseAndCheckList(PEG.string, '"string"', ["string"])

    def test_bare_word(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.bare_word, "a0bc_", ["a0bc_"])
        self.assertParseAndCheckList(PEG.bare_word, "_a0bc", ["_a0bc"])

        with self.assertRaisesParseException():
            self.assertParseAndCheckList(PEG.bare_word, "0abc", [])

    def test_method(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.method, "a0bc_", ["a0bc_"])
        self.assertParseAndCheckList(PEG.method, "_a0bc", ["_a0bc"])

        with self.assertRaisesParseException():
            self.assertParseAndCheckList(PEG.method, "0abc", [])

    def test_number(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.number, "42", [42])
        self.assertParseAndCheckList(PEG.number, "-42", [-42])
        self.assertParseAndCheckList(PEG.number, "42.42", [42.42])
        self.assertParseAndCheckList(PEG.number, "-42.42", [-42.42])

    def test_regexp(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.regexp, "/rgx/", ["rgx"])

    def test_ipv4(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.ipv4, "127.0.0.1", [IPv4Address("127.0.0.1")])
        self.assertParseAndCheckList(PEG.ipv4, "0.0.0.0", [IPv4Address("0.0.0.0")])
        self.assertParseAndCheckList(PEG.ipv4, "255.255.255.255", [IPv4Address("255.255.255.255")])

    def test_ipv6(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.ipv6, "::", [IPv6Address("::")])
        self.assertParseAndCheckList(PEG.ipv6, "::1", [IPv6Address("::1")])
        self.assertParseAndCheckList(PEG.ipv6, "::ffff:0.0.0.0", [IPv6Address("::ffff:0.0.0.0")])
        self.assertParseAndCheckList(PEG.ipv6, "64:ff9b:1:ffff:ffff:ffff:ffff:ffff", [IPv6Address("64:ff9b:1:ffff:ffff:ffff:ffff:ffff")])
        self.assertParseAndCheckList(PEG.ipv6, "fc00::", [IPv6Address("fc00::")])
        self.assertParseAndCheckList(PEG.ipv6, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", [IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")])

    def test_ip(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.ip, '"127.0.0.1"', [IPv4Address("127.0.0.1")])
        self.assertParseAndCheckList(PEG.ip, "'127.0.0.1'", [IPv4Address("127.0.0.1")])
        self.assertParseAndCheckList(PEG.ip, '"::1"', [IPv6Address("::1")])
        self.assertParseAndCheckList(PEG.ip, "'::1'", [IPv6Address("::1")])

    def test_true(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.true, "true", [True])

    def test_false(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.false, "false", [False])

    def test_boolean(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.boolean, "true", [True])
        self.assertParseAndCheckList(PEG.boolean, "false", [False])

    def test_plugin_type(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.plugin_type, "input", ["input"])
        self.assertParseAndCheckList(PEG.plugin_type, "filter", ["filter"])
        self.assertParseAndCheckList(PEG.plugin_type, "output", ["output"])

    def test_name(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.name, "word_1", ["word_1"])
        self.assertParseAndCheckList(PEG.name, "'string'", ["string"])
        self.assertParseAndCheckList(PEG.name, '"string"', ["string"])

    def test_selector_element(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.selector_element, "[string]", ["[", "string", "]"])

        with self.assertRaisesParseException():
            self.assertParseAndCheckList(PEG.selector_element, "[str,ing]", [])

    def test_selector(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.selector, "[str1][str2][str3]", ["[str1][str2][str3]"])

    def test_hash_entry(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.hash_entry, "42 => 42", [[42, [42]]])
        self.assertParseAndCheckList(PEG.hash_entry, "42    => \t 42", [[42, [42]]])
        self.assertParseAndCheckList(PEG.hash_entry, "bareword => bareword", [["bareword", ["bareword"]]])
        self.assertParseAndCheckList(PEG.hash_entry, "'string' => 'string'", [["string", ["string"]]])
        self.assertParseAndCheckList(PEG.hash_entry, '"string" => "string"', [["string", ["string"]]])

    def test_hash_entries(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.hash_entries, "name1 => value1 name2 => value2", [[["name1", ["value1"]], ["name2", ["value2"]]]])

    def test_hashmap(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.hashmap, "{ name1 => value1 }", [[["name1", ["value1"]]]])
        self.assertParseAndCheckList(PEG.hashmap, """
        {
        # comment
        name1 => value1 # comment
        # comment
        }
        """, [[["name1", ["value1"]]]])

    def test_array(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.array, "[ ]", [[]])
        self.assertParseAndCheckList(PEG.array, "[ 42,     bare_word, \t 'string' ]", [[42, "bare_word", "string"]])
        self.assertParseAndCheckList(PEG.array, "[ 42, bare_word, [ sub_array, 'value' ] ]", [[42, "bare_word", ["sub_array", "value"]]])

    def test_attribute(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.attribute, "name_1 => value1", [["name_1", ["value1"]]])

    def test_compare_expression(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.compare_expression, "42 == 42", [42, "==", 42])
        self.assertParseAndCheckList(PEG.compare_expression, "42 != 'string'", [42, "!=", "string"])
        self.assertParseAndCheckList(PEG.compare_expression, "[one]    < \t [two]", ["[one]", "<", "[two]"])

    def test_in_expression(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.in_expression, "2    in \t '42'", [2, "in", "42"])

    def test_not_in_expression(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.not_in_expression, "3   not  \t  in \t '42'", [3, "not", "in", "42"])

    def test_regexp_expression(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.regexp_expression, "[some][name]   =~ \t 'string'", ["[some][name]", "=~", "string"])
        self.assertParseAndCheckList(PEG.regexp_expression, "[some][name]   =~ \t /rgx/", ["[some][name]", "=~", "rgx"])

    def test_method_call(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.method_call, "method_name  ( 'rval1', \t 42 )", ["method_name", ["rval1", 42]])

    def test_plugin(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.plugin, "plugin_name  { name_1 => 42 name_2 => bare_word }", [["plugin_name", [["name_1", [42]], ["name_2", ["bare_word"]]]]])

    def test_plugin_section(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.plugin_section, "input { beats { port => 42 } }", [["input", [["beats", [["port", [42]]]]]]])

    def test_condition(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.condition, "'a' in 'abc' and 'b'     not in 'ok' or      1 < 2 ", [["a", "in", "abc"], "and", ["b", "not", "in", "ok"], "or", [1, "<", 2]])

    def test_if_rule(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.if_rule, "if [some][true][value] { plugin_name { name_1 => 42 } }",
                                     [["if", [["[some][true][value]"], [[["plugin_name", [["name_1", [42]]]]]]]]])

    def test_else_if_rule(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.else_if_rule, "else   \t  if [some][true][value] { plugin_name { name_1 => 42 } }",
                                     [["else if", [["[some][true][value]"], [[["plugin_name", [["name_1", [42]]]]]]]]])

        self.assertParseAndCheckList(PEG.else_if_rule, "else  \n#comment\r\n  if [some][true][value] { plugin_name { name_1 => 42 } }",
                                     [["else if", [["[some][true][value]"], [[["plugin_name", [["name_1", [42]]]]]]]]])

    def test_else_rule(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.else_rule, "else  \t  { plugin_name { name_1 => 42 } }", [["else", [["plugin_name", [["name_1", [42]]]]]]])

    def test_negative_expression(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.negative_expression, "! [sel][ector]", ["!", "[sel][ector]"])
        self.assertParseAndCheckList(PEG.negative_expression, "! ( 1 < 2) ", ["!", [1, "<", 2]])

    def test_branch(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.branch, """
        if 1 < 2 {
          plugin1 {
            name_1 => 42
          }
        }""", [
            ["if", [
                [1, "<", 2], [
                    [
                        ["plugin1", [
                            ["name_1", [42]]
                        ]]
                    ]
                ]
            ]]
        ])

        self.assertParseAndCheckList(PEG.branch, """
        if 1 < 2 {
          plugin1 {
            name_1 => 42
          }
        }
        else {
          plugin2 {
            name_1 => 42
          }
        }""", [
            ["if", [
                [1, "<", 2], [
                    [
                        ["plugin1", [
                            ["name_1", [42]]
                        ]]
                    ]
                ]
            ]],
            ["else", [
                ["plugin2", [
                    ["name_1", [42]]
                ]]
            ]]
        ])

        self.assertParseAndCheckList(PEG.branch, """
        if 1 < 2 {
          plugin1 {
            name_1 => 42
          }
        }

        else if [some][true][value] {
          plugin2 {
            name_1 => 42
          }
        }

        else {
          plugin3 {
            name_1 => 42
          }
        }""", [
            ["if", [
                [1, "<", 2], [
                    [
                        ["plugin1", [
                            ["name_1", [42]]
                        ]]
                    ]
                ]
            ]],
            ["else if", [
                ["[some][true][value]"], [
                    [
                        ["plugin2", [
                            ["name_1", [42]]
                        ]]
                    ]
                ]
            ]],
            ["else", [
                ["plugin3", [["name_1", [42]]]]
            ]]
        ])

    def test_config(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.config, """
        input {
          plugin1 {
            name_1 => 42
          }
        }

        filter {
          plugin2 {
            name_1 => 42
          }
        }

        output {
          plugin3 {
            name_1 => 42
          }
        }""", [
            ["input", [
                ["plugin1", [
                    ["name_1", [42]]
                ]]
            ]],
            ["filter", [
                ["plugin2", [
                    ["name_1", [42]]
                ]]
            ]],
            ["output", [
                ["plugin3", [
                    ["name_1", [42]]
                ]]
            ]]
        ])

    def test_complex(self) -> NoReturn:
        self.assertParseAndCheckList(PEG.config, r"""
            input {
                some_plugin {
                    config_mode => "advanced"
                    threads => 8
                    decorate_events => true # comment behind value
                    storage_connection => "DefaultEndpointsProtocol..."
                    # array
                    event_hubs => [
                        42,
                        "double quoted",
                        "single quoted",
                        # hashmap
                        {
                            # hashentry => hashmap
                            "insights-operational-logs" => {
                                # hashentry
                                event_hub_connection => "Endpoint=sb://example1..."
                                initial_position => "beginning"
                                consumer_group => "iam_team"
                            }
                        # trailing comma
                        },
                    ]
                }
            }

            filter {
                if [log][file][path] in ["/path/one", "/path/two"] {
                    grok {
                      match => { "original_message" => "\[(?<timestamp>%{YEAR}...\"%{GREEDYDATA:message}\""}
                    }
                    date {
                      match => [ "timestamp", "yyyy-MM-dd HH:mm:ss Z" ]
                    }
                }

                else if 1 < 42
                {
                    grok {
                      match => { "original_message" => "double quoted grok pattern"}
                    }

                    if "_grokparsefailure" not in [tags] {
                        date {
                            match => [ "timestamp", "ISO8601" ]
                        }
                    }
                }
                else {
                    mutate {
                        convert => {
                            "fieldname" => "integer"
                            "booleanfield" => "boolean"
                        }
                        copy => { "source_field" => "dest_field" }
                        gsub => [
                            # replace all forward slashes with underscore
                            "fieldname", "/", "_",
                            # replace backslashes, question marks, hashes, and minuses
                            # with a dot "."
                            "fieldname2", "[\\?#-]", "."
                        ]
                    }
                    mutate { add_field => { "[field][keyword]" => "TEST-SOMEDATA" } }

                    if [field][keyword] =~ /^(TEST|test)-.*$/ {
                        mutate { add_tag => [ "TEST" ] }
                    }
                }
            }

            output {
                file {
                    path => "/tmp/output.txt"
                    codec => line { format => "custom format: %{message}"}
                }
            }

            output {

                elasticsearch
                {
                    hosts => ["https://elasticnode01.local:9200", "https://elasticnode02.local:9200"]

                    index => "elk-filebeat-%{[agent][version]}-%{+YYYY}"
                    ssl => true
                    ssl_certificate_verification => false # comment
                    keystore => "/etc/logstash/certs/czsrv-jerlogstash01.p12"
                    keystore_password => "${elasticsearch.keystore.password}"
                    truststore => "/etc/logstash/certs/czsrv-jerlogstash01.p12"
                    truststore_password => "${elasticsearch.keystore.password}"

                    user => "logstash"
                    password => "${elasticsearch.logstash.password}"

                    manage_template => false
                }
            }
        """, [
            ["input", [
                ["some_plugin", [
                    ["config_mode", ["advanced"]],
                    ["threads", [8]],
                    ["decorate_events", [True]],
                    ["storage_connection", ["DefaultEndpointsProtocol..."]],
                    ["event_hubs", [
                        [42, "double quoted", "single quoted", [
                            ["insights-operational-logs", [
                                [
                                    ["event_hub_connection", ["Endpoint=sb://example1..."]],
                                    ["initial_position", ["beginning"]],
                                    ["consumer_group", ["iam_team"]]
                                ]
                            ]]
                        ]]
                    ]]
                ]]
            ]],
            ["filter", [
                ["if", [
                    ["[log][file][path]", "in", ["/path/one", "/path/two"]], [
                        [
                            ["grok", [
                                ["match", [
                                    [
                                        ["original_message", ['[(?<timestamp>%{YEAR}..."%{GREEDYDATA:message}"']]
                                    ]
                                ]]
                            ]],
                            ["date", [
                                ["match", [
                                    ["timestamp", "yyyy-MM-dd HH:mm:ss Z"]
                                ]]
                            ]]
                        ]
                    ]
                ]],
                ["else if", [
                    [1, "<", 42], [
                        [
                            ["grok", [
                                ["match", [
                                    [
                                        ["original_message", ["double quoted grok pattern"]]
                                    ]
                                ]]
                            ]],
                            ["if", [
                                ["_grokparsefailure", "not", "in", "[tags]"], [
                                    [
                                        ["date", [
                                            ["match", [
                                                ["timestamp", "ISO8601"]
                                            ]]
                                        ]]
                                    ]
                                ]
                            ]]
                        ]
                    ]
                ]],
                ["else", [
                    ["mutate", [
                        ["convert", [
                            [
                                ["fieldname", ["integer"]],
                                ["booleanfield", ["boolean"]]
                            ]
                        ]],
                        ["copy", [
                            [
                                ["source_field", ["dest_field"]]
                            ]
                        ]],
                        ["gsub", [
                            ["fieldname", "/", "_", "fieldname2", "[\\?#-]", "."]
                        ]]
                    ]],
                    ["mutate", [
                        ["add_field", [
                            [
                                ["[field][keyword]", ["TEST-SOMEDATA"]]
                            ]
                        ]]
                    ]],
                    ["if", [
                        ["[field][keyword]", "=~", "^(TEST|test)-.*$"], [
                            [
                                ["mutate", [
                                    ["add_tag", [
                                        ["TEST"]
                                    ]]
                                ]]
                            ]
                        ]
                    ]]
                ]]
            ]],
            ["output", [
                ["file", [
                    ["path", ["/tmp/output.txt"]],
                    ["codec", [
                        ["line", [
                            ["format", ["custom format: %{message}"]]
                        ]]
                    ]]
                ]]
            ]],
            ["output", [
                ["elasticsearch", [
                    ["hosts", [
                        ["https://elasticnode01.local:9200", "https://elasticnode02.local:9200"]
                    ]],
                    ["index", ["elk-filebeat-%{[agent][version]}-%{+YYYY}"]],
                    ["ssl", [True]],
                    ["ssl_certificate_verification", [False]],
                    ["keystore", ["/etc/logstash/certs/czsrv-jerlogstash01.p12"]],
                    ["keystore_password", ["${elasticsearch.keystore.password}"]],
                    ["truststore", ["/etc/logstash/certs/czsrv-jerlogstash01.p12"]],
                    ["truststore_password", ["${elasticsearch.keystore.password}"]],
                    ["user", ["logstash"]],
                    ["password", ["${elasticsearch.logstash.password}"]],
                    ["manage_template", [False]]
                ]]
            ]]
        ])


if __name__ == "__main__":
    unittest.main()
