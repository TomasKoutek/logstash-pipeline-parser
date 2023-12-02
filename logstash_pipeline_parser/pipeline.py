from collections.abc import Generator
from typing import NoReturn
from typing import Optional

from .tree import AST


class Pipeline:

    def __init__(self) -> NoReturn:
        self._ast = AST()

    def parse(self, pipeline: str) -> list:
        return self._ast.parse(pipeline)

    def search(self, key: str, pipeline: str) -> Generator[tuple, None, None]:
        key = key.split(".")
        # TODO ?
        if key[-1] == "*":
            msg = "Wildcard is not supported at the end of the key."
            raise ValueError(msg)

        for element in self._ast.parse(pipeline):
            yield from Pipeline._recursive_search(key, element)

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
    def _recursive_search(key: list, _element: list, _actual_key: Optional[list] = None) -> list[tuple[str, str | int | float | list]]:

        if _actual_key is None:
            _actual_key = []

        _actual_key = _actual_key.copy()
        _matched = []

        if isinstance(_element, list):

            if len(_element) == 2 and isinstance(_element[0], str):
                _actual_key.append(_element[0])

            if Pipeline._matcher(_actual_key, key):
                _matched.append((".".join(_actual_key), _element[1]))
            else:
                for _sub in _element:
                    if not isinstance(_sub, list):
                        continue
                    _matched += Pipeline._recursive_search(key, _sub, _actual_key)

        return _matched
