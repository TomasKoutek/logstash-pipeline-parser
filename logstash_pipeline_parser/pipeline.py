from collections.abc import Callable
from collections.abc import Generator
from pathlib import Path
from typing import Any
from typing import NoReturn
from typing import Optional
from typing import Self

from .tree import AST


class Pipeline:

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

    def add_type(self, name: str, new_type: type[Any] | Callable[[Any], Any]) -> Self:
        self._ast.add_type(name, new_type)
        return self

    def remove_type(self, name: str) -> Self:
        self._ast.remove_type(name)
        return self

    def get_types(self) -> dict:
        return self._ast.get_types()

    @classmethod
    def from_file(cls, path: str | Path) -> Self:
        if isinstance(path, str):
            path = Path(path)

        return cls(path.read_text())

    def parse(self) -> list:
        return self._ast.parse_config(self._data)

    def search(self, key: str) -> Generator[tuple, None, None]:

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
