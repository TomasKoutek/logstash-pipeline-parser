from typing import NoReturn

import dash_cytoscape as cyto
from dash import Dash
from dash import html

from logstash_pipeline_parser import Pipeline

data = r"""

input {
  syslog {
    port => 5144
    host => "0.0.0.0"
    grok_pattern => "^<%{POSINT:priority}>1 %{TIMESTAMP_ISO8601:timestamp8601} %{SYSLOGHOST:logsource} %{SYSLOGPROG} - %{NUMBER:msgid} %{GREEDYDATA:message}"
  }
  
  jdbc {
    jdbc_connection_string => "jdbc:postgresql://192.168.0.1:5432/mydb"
    jdbc_user => "logstash07"
    jdbc_password => "${mypipeline.logstash07.password}"
    schedule => "* * * 1 *"
    statement => "SELECT * FROM vw_example WHERE id > :sql_last_value"
    use_column_value => true
    tracking_column => id
    tracking_column_type => numeric
  }
}

filter {

  mutate {
    rename => ["host", "hostname" ]
    replace => { "hostname" => "%{hostname}" }
  }
  
  date {
    match => ["timestamp", "ISO8601"]
    id => "filter_date_timestamp"
  }
  
  translate {
      source => "host"
      target => "host"
      override => "true"
      dictionary => {
        "127.0.0.1" => "localhost"
      }
  }
  
  if [audit.type] == "USER_CMD" {

      grok {
        match => { "audit.message.raw" => "..some grok pattern" }
        id => "filter_grok_usercmd"
      }

      if [audit.mesagge.cmd] =~ /^[0-9A-F]*$/ {

        mutate {
          rename => { "audit.mesagge.cmd" => "audit.mesagge.cmd_hex" }
          id => "filter_mutate_rename_cmd"
        }

        ruby {
          code => "event.set('audit.mesagge.cmd', event.get('audit.mesagge.cmd_hex').gsub(/../) { |pair| pair.hex.chr })"
          id => "filter_ruby_hex_to_ascii"
        }
      }
  }
  else if [audit.type] == "SYSCALL" {

    grok {
      match => { "audit.message.raw" => "...some grok pattern ..." }
      id => "filter_grok_message_syscall"
    }
  }
}

output {

  elasticsearch
  {
    hosts => ["elasticnode01.local:9200", "elasticnode02.local:9200"]
    index => "example"
    ssl => true
    ssl_certificate_verification => true
    user => "logstash"
    password => "${elasticsearch.logstash.password}"
    manage_template => false
  }
}

"""


class Node:

    def __init__(self, node_id: int, name: str) -> NoReturn:
        self.id = node_id
        self.name = name

    def __str__(self) -> str:
        return f"Node(id: {self.id}, {self.name})"

    def __repr__(self) -> str:
        return self.__str__()


class Edge:

    def __init__(self, from_node: Node, to_node: Node) -> NoReturn:
        self.from_node = from_node
        self.to_node = to_node

    def __str__(self) -> str:
        return f"Edge({self.from_node} -> {self.to_node}"

    def __repr__(self) -> str:
        return self.__str__()


class Graph:

    def __init__(self) -> NoReturn:
        self.nodes: list[Node] = []
        self.edges: list[Edge] = []

    def create_node(self, name: str) -> Node:
        node_id = len(self.nodes) + 1
        node = Node(node_id, name)
        self.nodes.append(node)
        return node

    def add_edge(self, from_node: Node, to_node: Node) -> Edge:
        edge = Edge(from_node, to_node)
        self.edges.append(edge)
        return edge

    def to_cytoscape(self) -> list:
        nodes = [{"data": {"id": str(n.id), "label": str(n.name)}} for n in self.nodes]
        edges = [{"data": {"source": str(edge.from_node.id), "target": str(edge.to_node.id)}} for edge in self.edges]

        return nodes + edges


def recurse_keys(graph: Graph, element: list, parent_node: Node = None) -> NoReturn:
    if len(element) == 2 and isinstance(element[0], str) and isinstance(element[1], list):
        node = graph.create_node(element[0])

        if parent_node:
            graph.add_edge(parent_node, node)

        recurse_keys(graph, element[1], node)

    else:
        for child in element:
            if isinstance(child, list):
                recurse_keys(graph, child, parent_node)


class Dashboard:

    def __init__(self, graph: Graph) -> NoReturn:
        self.graph = graph

    def create(self) -> Dash:
        dash: Dash = Dash(name=__name__)

        dash.layout = html.Div([
            cyto.Cytoscape(
                id="cytoscape-bfs",
                responsive=True,
                # BFS - https://js.cytoscape.org/#layouts/breadthfirst
                layout={
                    "name": "breadthfirst",
                    "directed": True,
                    "animate": False,
                },
                style={
                    "width": "100%",
                    "height": "800px",
                },
                elements=self.graph.to_cytoscape(),
                stylesheet=[
                    {
                        "selector": "node",
                        "style": {
                            "content": "data(label)",
                        }
                    },
                    {
                        "selector": "edge",
                        "style": {
                            "curve-style": "bezier",
                            "target-arrow-shape": "triangle",
                            "width": 3,
                            "line-color": "#61bffc",
                            "target-arrow-color": "#61bffc",
                        },
                    },
                ],
            )
        ])

        return dash


def main() -> NoReturn:
    pipeline = Pipeline(data)
    graph = Graph()
    recurse_keys(graph, pipeline.parse())
    Dashboard(graph).create().run(host="127.0.0.1", port=8060, debug=True)


if __name__ == "__main__":
    main()
