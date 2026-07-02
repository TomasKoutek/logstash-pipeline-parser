About
=====

**Logstash pipeline parser** |version|

.. graphviz::
   :name: graph

   digraph G {
     compound=true;
     ratio="compress"

     subgraph cluster_0 {
       label = "plugin";
       1 [label="input"];

       1 -> 2;

       subgraph cluster_7 {
         label = "plugin type";
         style = "dashed"
         labelloc="bottom";

         2 [label="syslog"];
         3 [label="port"];
         4 [label="5044"];
         5 [label="codec"];
         6 [label="cef"];

         2 -> {3 5};
         3 -> 4;
         5 -> 6;
       }
     }

     subgraph cluster_2 {
       label = "plugin";

       16 [label="filter"];
       17 [label="if"];
       24 [label="else if"];

       subgraph cluster_6 {
         label = "filter plugin";
         style = "dashed";
         labelloc="bottom";

         21 [label="copy"];
         22 [label="source"];
         23 [label="target"];

         21 -> 22;
         22 -> 23;
       }

       subgraph cluster_8 {
         label = "filter plugin";
         style = "dashed";
         labelloc="bottom";

         33 [label="json"];
         34 [label="message"];
         35 [label="target"];
         36 [label="source"];
         37 [label="doc"];

         33 -> {35 36};
         36 -> 34;
         35 -> 37;
       }

       subgraph cluster_9 {
         label = "filter plugin";
         style = "dashed";
         labelloc="bottom";

         38 [label="mutate"];
         39 [label="rename"];
         40 [label="shortHostname"];
         41 [label="hostname"];

         38 -> 39;
         39 -> 40;
         40 -> 41;
       }

       subgraph cluster_3 {
         label = "condition";
         labelloc="bottom";
         style = "dashed";

         20 [label="42" constraint=false];
         19 [label=">=" constraint=false];
         18 [label="[field]" constraint=false];
       }

       subgraph cluster_5 {
         label = "filter plugin";
         style = "dashed";
         labelloc="bottom";

         25 [label="mutate"];
         26 [label="convert"];
         27 [label="field"];
         28 [label="integer"];

         25 -> 26;
         26 -> 27;
         27 -> 28;
       }

       subgraph cluster_4 {
         label = "condition";
         labelloc="bottom"
         style = "dashed";
         labelloc="bottom";

         32 [label="path2"];
         31 [label="path1"];
         30 [label="in"];
         29 [label="[path]"];
       }

       16 -> {24 17};

       30 -> 38 [ltail=cluster_4 minlen=2];
       30 -> 33 [ltail=cluster_4 minlen=2];
       30 -> 21 [ltail=cluster_4 minlen=2];
       19 -> 25 [ltail=cluster_3 minlen=2];
       17 -> {18 19 20};
       24 -> {29 30 31 32};
     }

     subgraph cluster_1 {
       label = "plugin";
       7 [label="output"];

       7 -> 8;

       subgraph cluster_10 {
         label = "plugin type";
         labelloc="bottom";
         style = "dashed";
         labelloc="bottom";

         8 [label="elasticsearch"];
         9 [label="index"];
         10 [label="my-index"];
         13 [label="hosts"];
         14 [label="es-host1"];
         15 [label="es-host2"];

         8 -> {9 13};
         9 -> 10;
         13 -> {14 15};

       }
     }
   }


What is Logstash pipeline
-------------------------

*The Logstash event processing pipeline has three stages: inputs → filters → outputs.
Inputs generate events, filters modify them, and outputs ship them elsewhere.
Inputs and outputs support codecs that enable you to encode or decode the data as it enters or exits the pipeline without having to use a separate filter.*

The pipeline configuration file is a custom format developed by the Logstash folks using `Treetop <https://cjheath.github.io/treetop/syntactic_recognition.html>`_.
The grammar itself is described in the source file `grammar.treetop <https://github.com/elastic/logstash/tree/v8.11.1/logstash-core/lib/logstash/config/grammar.treetop>`_ and compiled using Treetop into the custom `grammar.rb <https://github.com/elastic/logstash/blob/v8.11.1/logstash-core/lib/logstash/config/grammar.rb>`_ parser.
That parser is then used to set up the pipeline from the Logstash configuration.

.. seealso::

    - `How Logstash Works <https://www.elastic.co/guide/en/logstash/current/pipeline.html>`_
    - `Creating a Logstash pipeline <https://www.elastic.co/guide/en/logstash/current/configuration.html>`_


Dependencies
------------

The parser has only one dependency on the `pyparsing <https://github.com/pyparsing/pyparsing>`_ package for creating `PEG parser <https://en.wikipedia.org/wiki/Parsing_expression_grammar>`_


Issue tracking
--------------

You can find existing and fixed bugs by clicking on `Issues <https://github.com/TomasKoutek/logstash-pipeline-parser/issues>`_ and using "New Issue"
to report previously unknown issues.
