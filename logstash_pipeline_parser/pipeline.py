from collections.abc import Callable
from collections.abc import Generator
from pathlib import Path
from typing import Any
from typing import NoReturn
from typing import Optional
from typing import Self

from .tree import AST


class Pipeline:
    """
    :param pipeline: The pipeline definition
    :type pipeline: str

    A class representing the Logstash pipeline.
    """  # noinspection

    def __init__(self, pipeline: str) -> NoReturn:

        self._ast: AST = AST()
        self._data: str = pipeline

        # Path type
        self._ast \
            .add_type("aggregate_maps_path", Path) \
            .add_type("cacert", Path) \
            .add_type("ca_file", Path) \
            .add_type("client_cert", Path) \
            .add_type("client_key", Path) \
            .add_type("database", Path) \
            .add_type("dictionary_path", Path) \
            .add_type("jaas_path", Path) \
            .add_type("jdbc_driver_library", Path) \
            .add_type("jdbc_password_filepath", Path) \
            .add_type("json_key_file", Path) \
            .add_type("kerberos_config", Path) \
            .add_type("keystore", Path) \
            .add_type("mib_paths", Path) \
            .add_type("network_path", Path) \
            .add_type("path", Path) \
            .add_type("private_key", Path) \
            .add_type("processed_db_path", Path) \
            .add_type("public_key", Path) \
            .add_type("schema_registry_ssl_keystore_location", Path) \
            .add_type("schema_registry_ssl_truststore_location", Path) \
            .add_type("send_nsca_config", Path) \
            .add_type("ssl_cacert", Path) \
            .add_type("ssl_cert", Path) \
            .add_type("ssl_certificate", Path) \
            .add_type("ssl_certificate_path", Path) \
            .add_type("ssl_key", Path) \
            .add_type("ssl_keystore_location", Path) \
            .add_type("ssl_keystore_path", Path) \
            .add_type("ssl_truststore_location", Path) \
            .add_type("ssl_truststore_path", Path) \
            .add_type("statement_filepath", Path) \
            .add_type("template", Path) \
            .add_type("template_file", Path) \
            .add_type("truststore", Path)

    @classmethod
    def from_file(cls, path: str | Path) -> Self:
        """
        :param path: Path to the file
        :type path: str | pathlib.Path
        :rtype: Pipeline

        Instantiates class from a file.

        For example from string:

        .. code-block:: python

           from logstash_parser import Pipeline

           pipeline = Pipeline.from_file("/some/path/to/pipeline.conf")

        Or from Path:

        .. code-block:: python

           from logstash_parser import Pipeline
           from pathlib import Path

           path = Path("/some/path/to/pipeline.conf")
           pipeline = Pipeline.from_file(path)
        """  # noinspection

        if isinstance(path, str):
            path = Path(path)

        return cls(path.read_text())

    def add_type(self, name: str, new_type: type[Any] | Callable[[Any], Any]) -> Self:
        """
        :param name: Type name
        :type name: str
        :param new_type: New type for given name.
        :type new_type: type[typing.Any] | typing.Callable[[typing.Any], typing.Any]
        :rtype: Pipeline

        Adds a new type.

        For example function:

        .. code-block:: python

           from logstash_parser import Pipeline

           Pipeline("").add_type("port", str)

        For example class:

        .. code-block:: python

           from logstash_parser import Pipeline

           class MyPortType:
               pass

           Pipeline("").add_type("port", MyPortType)

        .. note::

           Please see :ref:`examples-type` for more examples.
        """  # noinspection

        self._ast.add_type(name, new_type)
        return self

    def remove_type(self, name: str) -> Self:
        """
        :param name: Type name
        :type name: str
        :rtype: Pipeline

        Removes a type

        For example function:

        .. code-block:: python

           from logstash_parser import Pipeline

           Pipeline("").remove_type("port")
        """  # noinspection

        self._ast.remove_type(name)
        return self

    def get_types(self) -> dict[str, type[Any] | Callable[[Any], Any]]:
        """
        :return: All names as key and types as value.
        :rtype: dict

        Returns all defined types

        Predefined types are:

        .. list-table::
           :header-rows: 1
           :widths: auto

           * - Name
             - Type/Callable
           * - aggregate_maps_path
             - :py:class:`pathlib.Path`
           * - cacert
             - :py:class:`pathlib.Path`
           * - ca_file
             - :py:class:`pathlib.Path`
           * - client_cert
             - :py:class:`pathlib.Path`
           * - client_key
             - :py:class:`pathlib.Path`
           * - database
             - :py:class:`pathlib.Path`
           * - dictionary_path
             - :py:class:`pathlib.Path`
           * - jaas_path
             - :py:class:`pathlib.Path`
           * - jdbc_driver_library
             - :py:class:`pathlib.Path`
           * - jdbc_password_filepath
             - :py:class:`pathlib.Path`
           * - json_key_file
             - :py:class:`pathlib.Path`
           * - kerberos_config
             - :py:class:`pathlib.Path`
           * - keystore
             - :py:class:`pathlib.Path`
           * - mib_paths
             - :py:class:`pathlib.Path`
           * - network_path
             - :py:class:`pathlib.Path`
           * - path
             - :py:class:`pathlib.Path`
           * - private_key
             - :py:class:`pathlib.Path`
           * - processed_db_path
             - :py:class:`pathlib.Path`
           * - public_key
             - :py:class:`pathlib.Path`
           * - schema_registry_ssl_keystore_location
             - :py:class:`pathlib.Path`
           * - schema_registry_ssl_truststore_location
             - :py:class:`pathlib.Path`
           * - send_nsca_config
             - :py:class:`pathlib.Path`
           * - ssl_cacert
             - :py:class:`pathlib.Path`
           * - ssl_cert
             - :py:class:`pathlib.Path`
           * - ssl_certificate
             - :py:class:`pathlib.Path`
           * - ssl_certificate_path
             - :py:class:`pathlib.Path`
           * - ssl_key
             - :py:class:`pathlib.Path`
           * - ssl_keystore_location
             - :py:class:`pathlib.Path`
           * - ssl_keystore_path
             - :py:class:`pathlib.Path`
           * - ssl_truststore_location
             - :py:class:`pathlib.Path`
           * - ssl_truststore_path
             - :py:class:`pathlib.Path`
           * - statement_filepath
             - :py:class:`pathlib.Path`
           * - template
             - :py:class:`pathlib.Path`
           * - template_file
             - :py:class:`pathlib.Path`
           * - truststore
             - :py:class:`pathlib.Path`
        """  # noinspection

        return self._ast.get_types()

    def parse(self) -> list:
        """
        :return: Parsed tree
        :rtype: list

        Create an `Abstract syntax tree <https://en.wikipedia.org/wiki/Abstract_syntax_tree>`_  from the input data.
        Of course, it is possible to parse all kinds of plugins, conditions and data types.

        For example this input:

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

        will produce this array:

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
        """  # noinspection

        return self._ast.parse_config(self._data)

    def search(self, key: str) -> Generator[tuple[str, Any], None, None]:
        """        
        :param key: Key name to search for
        :type key: str
        :return: Found values in the form tuple[key, value]
        :rtype: collections.abc.Generator[tuple[str, typing.Any], None, None]

        Yield the searched keys and their values from the tree.
        The key can also contain the wildcard `*`, for example "output.*.hosts" will return
        (if the pipeline definition contains them):

        .. code-block:: console

           - ("output.elasticsearch.hosts", ["127.0.0.1:9200","127.0.0.2:9200"])
           - ("output.logstash.hosts", "127.0.0.1:9801")

        .. note::

           Please see :ref:`examples-search` for more examples.
        """  # noinspection

        for element in self._ast.parse_config(self._data):
            yield from Pipeline._recursive_search(key.split("."), element)

    # thx Francois Garillot
    # https://stackoverflow.com/a/8848959
    @staticmethod
    def _matcher(_l1: list, _l2: list) -> bool:
        if not _l1:
            return _l2 == [] or _l2 == ["*"]
        if _l2 == [] or _l2[0] == "*":
            return Pipeline._matcher(_l2, _l1)
        if _l1[0] == "*":
            return Pipeline._matcher(_l1, _l2[1:]) or Pipeline._matcher(_l1[1:], _l2)
        if _l1[0] == _l2[0]:
            return Pipeline._matcher(_l1[1:], _l2[1:])
        else:
            return False

    @staticmethod
    def _recursive_search(key: list, element: list, actual_key: Optional[list] = None) -> list[tuple[str, Any]]:

        if actual_key is None:
            actual_key = []

        actual_key: list = actual_key.copy()
        _matched: list[tuple[str, Any]] = []

        if len(element) == 2 and isinstance(element[0], str):
            actual_key.append(element[0])

        if Pipeline._matcher(actual_key, key):
            _matched.append((".".join(actual_key), element[1]))
        else:
            for child in element:
                if not isinstance(child, list):
                    continue
                _matched += Pipeline._recursive_search(key, child, actual_key)

        return _matched
