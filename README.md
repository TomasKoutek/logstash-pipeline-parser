
## About The Project

### How Logstash Pipeline Works
> The Logstash event processing pipeline has three stages: inputs → filters → outputs.\
> Inputs generate events, filters modify them, and outputs ship them elsewhere.\
> Inputs and outputs support codecs that enable you to encode or decode the data as it enters or exits the pipeline without having to use a separate filter.

The pipeline configuration file is a custom format developed by the Logstash folks using [Treetop](https://cjheath.github.io/treetop/syntactic_recognition.html).
The grammar itself is described in the source file [grammar.treetop](https://github.com/elastic/logstash/tree/v8.11.1/logstash-core/lib/logstash/config/grammar.treetop) and compiled using Treetop into the custom [grammar.rb](https://github.com/elastic/logstash/blob/v8.11.1/logstash-core/lib/logstash/config/grammar.rb) parser.
That parser is then used to set up the pipeline from the Logstash configuration.

#### Documentation
- [pipeline](https://www.elastic.co/guide/en/logstash/current/pipeline.html)
- [configuration](https://www.elastic.co/guide/en/logstash/current/configuration.html)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

### Installing
```
pip install logstash-pipeline-parser
```

### Dependencies
- [pyparsing](https://github.com/pyparsing/pyparsing) for creating [PEG parser](https://en.wikipedia.org/wiki/Parsing_expression_grammar)

## Usage

The Pipeline class has currently two methods - `Pipeline.parse()` and `Pipeline.search()`.

The method `parse(pipeline: str) -> list` parse (PEG) input string and returns a simple syntax tree. 
Of course, it is possible to parse all kinds of plugins, conditions and data types.

The method `search(key: str, pipeline: str) -> Generator[tuple, None, None]` returns the searched keys and their values from the tree.
The key can also contain the wildcard `*`, for example "output.*.hosts" will return
(if the pipeline definition contains them):

- `("output.elasticsearch.hosts", ["127.0.0.1:9200","127.0.0.2:9200"])`
- `("output.logstash.hosts", "127.0.0.1:9801")`


### Examples

#### Parse

Let's try pipeline with one input plugin: 

```python
from logstash_pipeline_parser import Pipeline

ast = Pipeline().parse(r"""
input {
  beats {
    port => 5044
    client_inactivity_timeout => 3600
    include_codec_tag => true
    ssl => false
    id => "input_beats"
  }
}
""")

```

Will create simple [Abstract syntax tree](https://en.wikipedia.org/wiki/Abstract_syntax_tree):

```python
[
    ["input", [
         ["beats", [
              ["port", 5044], 
              ["client_inactivity_timeout", 3600], 
              ["include_codec_tag", "true"], 
              ["ssl", "false"], 
              ["id", "input_exec_beats"]
          ]]
     ]]
]
```


### Search

Let's define input with two plugins:  

```python
from logstash_pipeline_parser import Pipeline

pipe = Pipeline()
data = r"""
input {
  syslog {
    port => 123
    codec => cef
    some_key => {
      somekey => ["list", "of", "values"]
    }
  }

  udp {
    port => 456
    host => "0.0.0.0"
  }
}
"""
```

Now we can search by names separated by dot:

```python
results = pipe.search("input.syslog.port", data)
print(list(results))

> [('input.syslog.port', 123)]
```

We can replace the syslog name with a wildcard:

```python
results = pipe.search("input.*.port", data)
print(list(results))

> [('input.syslog.port', 123), ('input.udp.port', 456)]
```

Wildcard is greedy:

```python
results = pipe.search("*.port", data)
print(list(results))

> [('input.syslog.port', 123), ('input.udp.port', 456)]
```

The `search` method returns a generator, so we can easily iterate:

```python
for key, value in pipe.search("*.port", data):
    print(f"key: {key}, value: {value}")

> key: input.syslog.port, value: 123
> key: input.udp.sub.port, value: 456
```

The return value can be any element from the tree (integer, string, field, plugin,...):

```python
results = pipe.search("input.syslog.some_key", data)
print(list(results))

> [('input.syslog.some_key', [['somekey', ['list', 'of', 'values']]])]
```


## License

Distributed under the MIT License. See LICENSE for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
