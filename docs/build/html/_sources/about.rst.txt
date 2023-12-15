About
=====

**Logstash pipeline parser** |version|

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
