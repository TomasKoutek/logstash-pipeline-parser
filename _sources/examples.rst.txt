Examples
==============================

This code demonstrates usage of Logstash pipeline parser.
It gives you a good overview of all the things that can be done.
Also included is output so you can see what gets printed when you run the code.

Initialization
--------------

First of all we initialize :py:class:`Pipeline` from string

.. code-block:: python

   from logstash_pipeline_parser import Pipeline

   data = r"""
       input {
         syslog {
           port => 5014
         }
       }
   """

   pipeline = Pipeline(data)

Or it is possible to initialize the pipeline from a file.

.. code-block:: python

   from logstash_parser import Pipeline
   from pathlib import Path

   # string parameter
   pipeline = Pipeline.from_file("/some/path/to/pipeline.conf")

   # Path parameter
   path = Path("/some/path/to/pipeline.conf")
   pipeline = Pipeline.from_file(path)



.. _examples-parse:

Parsing
-------

Let's parse some beats input.

.. code-block:: python

   from logstash_pipeline_parser import Pipeline

   data = r\"""
       input {
         beats {
           host => "0.0.0.0"
           port => 5044
           client_inactivity_timeout => 3600
           include_codec_tag => true
           enrich => [source_metadata, ssl_peer_metadata]
           ssl => true
           ssl_key => "/some/path/my.key"
           id => "input_beats"
         }
       }
   \"""

   ast = Pipeline(data).parse()

This will produce array:

.. code-block:: python

   from ipaddress import IPv4Address
   from pathlib import Path

   [
       ["input",[
           ["beats", [
               ["host", [IPv4Address("0.0.0.0")]],
               ["port", [5044]],
               ["client_inactivity_timeout", [3600]],
               ["include_codec_tag", [True]],
               ["enrich", [
                   ["source_metadata", "ssl_peer_metadata"]
               ]],
               ["ssl", [True]],
               ["ssl_key", [Path("/some/path/my.key")]],
               ["id", ["input_beats"]]
           ]]
       ]]
   ]

.. note::

   Parser automatically casts boolean values, numbers, IPv4/IPv6 addresses and filesystem paths.


.. _examples-type:

Types
-----

Let's say:
 #. we don't want to return "include_codec_tag" as :py:class:`bool` but a simple :py:class:`str`.
 #. we don't want to return "ssl_key" as :py:class:`pathlib.Path` but a simple :py:class:`str`.
 #. we want "host" of type MyHost
 #. we want to return only the first value from "enrich".


.. code-block:: python

   from logstash_pipeline_parser import Pipeline
   from typing import NoReturn

   def return_first(data:list) -> str:
       return data[0]

   class MyHost:

       def __init__(self, data: Any) -> NoReturn:
           self.data = data

       def __repr__(self) -> str:
           return f"MyHost(data={self.data})"

   pipeline = Pipeline(data)

   # add new types
   pipeline.add_type('include_codec_tag', str)
   pipeline.add_type('host', MyHost)
   pipeline.add_type("enrich", return_first)

   # remove default type
   pipeline.remove_type('ssl_key')

   ast = pipeline.parse()

Of course these examples don't make much sense, it's just a usage example.
The parsing result is:

.. code-block:: python

   [
     ["input", [
       ["beats", [
         ["host", [MyHost(data=IPv4Address("0.0.0.0"))]],
         ["port", [5044]],
         ["client_inactivity_timeout", [3600]],
         ["include_codec_tag", ["True"]],
         ["enrich", ["source_metadata"]],
         ["ssl", [True]],
         ["ssl_key", ["/some/path/my.key"]],
         ["id", ["input_beats"]]
       ]]
     ]]
   ]

.. _examples-search:

Search
------

Let's define some test data in pipeline.

.. code-block:: python

   from logstash_pipeline_parser import Pipeline

   data = r\"""
       input {
         syslog {
           port => 123
           codec => cef
           severity_labels => ["Emergency", "Alert"]
         }

         udp {
           port => 456
           host => "0.0.0.0"
         }
        }
    \"""

    pipeline = Pipeline(data)

Now we can search by names separated by dot:

.. code-block:: python

   results = pipeline.search("input.syslog.port")

   print(list(results))
   # [
   #   ("input.syslog.port", [123])
   # ]

We can replace the "syslog" with a wildcard:

.. code-block:: python

   results = pipeline.search("input.*.port")

   print(list(results))
   # [
   #   ("input.syslog.port", [123]),
   #   ("input.udp.port", [456])
   # ]

Wildcard is greedy:

.. code-block:: python

   results = pipeline.search("*.port")

   print(list(results))
   # [
   #   ("input.syslog.port", [123]),
   #   ("input.udp.port", [456])
   # ]

The :py:class:`Pipeline.search` method returns a generator, so we can easily iterate:

.. code-block:: python

   for key, value in pipeline.search("*.port"):
       print(f"key: {key}, value: {value[0]}")

   # key: input.syslog.port, value: 123
   # key: input.udp.sub.port, value: 456

The return value can be any element from the tree (integer, string, field, plugin,...):

.. code-block:: python

   results = pipeline.search("input.syslog.severity_labels")

   print(list(results))
   # [("input.syslog.severity_labels", [["Emergency", "Alert"]])]

