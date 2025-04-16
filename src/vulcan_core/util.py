# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

import functools
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from dataclasses import dataclass
from functools import wraps
from typing import Any, NoReturn


@dataclass(frozen=True)
class WithContext:
    """Applies a context manager as a decorator.

    @WithContext(suppress(Exception))
        def foo():
            raise Exception("Some Exception")
    """

    context: AbstractContextManager

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with self.context:
                return func(*args, **kwargs)

        return wrapper


def not_implemented(func) -> Callable:
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> NoReturn:
        msg = f"{func.__name__} is not implemented."
        raise NotImplementedError(msg)

    return wrapper


def is_private(key: str) -> bool:
    return key.startswith("_")


class AttrDict(dict):
    def validate(self, key: str) -> str:
        if is_private(key):
            msg = f"Access denied to private attribute: {key}"
            raise KeyError(msg)

        if key not in self.__annotations__:
            raise KeyError(key)

        return key

    def __init__(self):
        if type(self) is AttrDict:
            msg = f"{AttrDict.__name__} is an abstract class that can not be directly instantiated."
            raise TypeError(msg)

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, self.validate(key))
        except KeyError:
            if hasattr(self, "__missing__"):
                return self.__missing__(key)  # type: ignore
            else:
                raise

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, self.validate(key), value)

    def __iter__(self) -> Iterator[str]:
        return (key for key in self.__annotations__ if not is_private(key))

    def __reversed__(self) -> Iterator[str]:
        return reversed(list(self))

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, self.validate(key))

    def __or__(self, other: dict) -> dict:
        return dict(self) | other

    def __repr__(self) -> str:
        return repr(dict(self))

    def keys(self) -> list[str]:
        return list(self)

    def values(self) -> list[Any]:
        return [getattr(self, key) for key in self]

    def items(self) -> list[tuple[str, Any]]:
        return [(key, getattr(self, key)) for key in self]

    def get(self, key: str, default: Any = None):
        return getattr(self, self.validate(key), default)

    def setdefault(self, key: str, default: Any = None) -> Any:
        if key not in self:
            self[key] = default
        return self[key]

    @not_implemented
    def __delitem__(self, key: str) -> NoReturn: ...

    @not_implemented
    def __ior__(self, other: dict[str, Any]) -> NoReturn: ...

    @not_implemented
    def clear(self) -> NoReturn: ...

    @not_implemented
    def copy(self) -> NoReturn: ...

    @not_implemented
    def pop(self, key: str, defaul: Any = None) -> NoReturn: ...

    @not_implemented
    def popitem(self) -> NoReturn: ...

    @not_implemented
    def update(self, *args, **kwargs) -> NoReturn: ...
