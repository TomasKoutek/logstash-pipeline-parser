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

    def add_type(self, name: str, new_type: type[Any] | Callable[[Any], Any]) -> Self:
        self._ast.add_type(name, new_type)
        return self

    def remove_type(self, name: str) -> Self:
        self._ast.remove_type(name)
        return self

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
