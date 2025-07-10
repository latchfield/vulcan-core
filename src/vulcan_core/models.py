# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from copy import copy
from dataclasses import dataclass
from enum import StrEnum, auto
from typing import (
    TYPE_CHECKING,
    Any,
    Protocol,
    Self,
    dataclass_transform,
    runtime_checkable,
)

from langchain.schema import Document

from vulcan_core.util import is_private

if TYPE_CHECKING:  # pragma: no cover - not used at runtime
    from functools import partial

    from langchain_core.vectorstores import VectorStoreRetriever

type ActionReturn = tuple[partial[Fact] | Fact, ...] | partial[Fact] | Fact
type ActionCallable = Callable[..., ActionReturn]
type ConditionCallable = Callable[..., bool | None]


# TODO: Consolidate with AttrDict, and/or figure out how to extende from Mapping
class ImmutableAttrAsDict:
    """
    ImmutableAttrAsDict is an abstract base class that provides dictionary-like access to its attributes.
    """

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, self.validate(key))
        except KeyError:
            if hasattr(self, "__missing__"):
                return self.__missing__(key)  # type: ignore
            else:
                raise

    def __contains__(self, key: str) -> bool:
        return hasattr(self, self.validate(key))

    def __iter__(self) -> Iterator[str]:
        return (key for key in self.__annotations__ if not is_private(key))

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def validate(self, key: str) -> str:
        if is_private(key):
            msg = f"Access denied to private attribute: {key}"
            raise KeyError(msg)

        if key not in self.__annotations__:
            raise KeyError(key)

        return key

    def __init__(self):
        if type(self) is ImmutableAttrAsDict:
            msg = f"{ImmutableAttrAsDict.__name__} is an abstract class that can not be directly instantiated."
            raise TypeError(msg)

    def __reversed__(self) -> Iterator[str]:
        return reversed(list(self))

    def __or__(self, other: dict) -> dict:
        return dict(self) | other

    def keys(self) -> list[str]:
        return list(self)

    def values(self) -> list[Any]:
        return [getattr(self, key) for key in self]

    def items(self) -> list[tuple[str, Any]]:
        return [(key, getattr(self, key)) for key in self]

    def get(self, key: str, default: Any = None):
        return getattr(self, self.validate(key), default)


@dataclass_transform(kw_only_default=True, frozen_default=True)
class FactMetaclass(type):
    """
    FactMetaclass is a metaclass that modifies the creation of new classes to automatically
    apply the `dataclass` decorator with `kw_only=True` and `frozen=True` options.
    """

    def __new__(cls, name: str, bases: tuple[type], class_dict: dict[str, Any], **kwargs: Any):
        self = super().__new__(cls, name, bases, class_dict, **kwargs)
        return dataclass(kw_only=True, frozen=True)(self)

    def _is_dataclass_instance(cls) -> bool:
        """Determine if this is a dataclass instance by looking for __dataclass_fields__"""
        return "__dataclass_fields__" not in super().__getattribute__("__dict__")

    # TODO: Implement a context manager to allow access to the default class values
    # BUG: This causes pylance to not report missing attributes, we need a different way to handle f strings... maybe
    # the __format__ method?
    def __getattribute__(cls, name):
        """
        Returns a {templated} representation of the Fact's public attributes for deferred use in fstrings. This is
        useful in rule clauses so that IDE autocomplete can be used in fstrings while deferring evaluation of
        the content."""
        if name.startswith("_") or cls._is_dataclass_instance():
            return super().__getattribute__(name)
        else:
            return f"{{{cls.__name__}.{name}}}"


class Fact(ImmutableAttrAsDict, metaclass=FactMetaclass):
    """
    An abstract class that must be used to define rule engine fact schemas and instantiate data into working memory. Facts
    may be combined with partial facts of the same type using the `|` operator. This is useful for Actions that only
    need to update a portion of working memory.

    Example: `new_fact = Inventory(apples=1) | partial(Inventory, oranges=2)`
    """

    def __or__(self, other: partial[Self] | Self) -> Self:
        """
        If the right hand operand is a Fact, it is returned as-is. However, if it is a partial Fact, a copy of the
        lefthand operand is created with the partial Fact's keywords applied.
        """
        if isinstance(other, Fact):
            if type(self) is not type(other):
                msg = f"Union operator disallowed for types {type(self).__name__} and {type(other).__name__}"
                raise TypeError(msg)

            return other  # type: ignore
        else:
            if type(self) is not other.func:
                msg = f"Union operator disallowed for types {type(self).__name__} and {other.func}"
                raise TypeError(msg)

            new_fact = copy(self)
            for kw, value in other.keywords.items():
                object.__setattr__(new_fact, kw, value)
            return new_fact  # type: ignore


@dataclass(frozen=True)
class DeclaresFacts(ABC):
    facts: tuple[str, ...]
    # TODO differentiate bettwen facts consumed vs produced for better tracking/diagnostics
    # Will probably be needed to detecte cycles in the graph


@dataclass(frozen=True)
class FactHandler[T: Callable, R: Any](ABC):
    func: T

    @abstractmethod
    def _evaluate(self, *args: Fact) -> R: ...


@runtime_checkable
class HasSource(Protocol):
    __source__: str


class ChunkingStrategy(StrEnum):
    SENTENCE = auto()
    PARAGRAPH = auto()
    PAGE = auto()


@dataclass(kw_only=True, slots=True)
class Similarity(Mapping[str, list[tuple[str, float]]]):
    # TODO: Figure out how to cache vectors / and results?

    @abstractmethod
    def __getitem__(self, key: str) -> list[str]:
        """Vectorizes key and performs similarity search returning a list of matching."""
        raise NotImplementedError

    @abstractmethod
    def __contains__(self, key: str) -> bool:
        """Vectorizes key and performs similarity search returning a boolean if there is at least one match."""
        raise NotImplementedError

    @abstractmethod
    def __iadd__(self, value: str) -> Self:
        raise NotImplementedError

    @abstractmethod
    def __iter__(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def __len__(self) -> int:
        raise NotImplementedError


class ProxyInitializationError(Exception):
    """Raised when a Proxy class is used without the proxy being initialized."""


@dataclass(kw_only=True, slots=True)
class ProxyLazyLookup(Similarity):
    _proxy: Similarity | None = None

    @property
    def proxy(self) -> Similarity:
        if self._proxy:
            return self
        else:
            msg = "The `proxy` attribute must be set before the class instance can be used."
            raise ProxyInitializationError(msg)

    @proxy.setter
    def proxy(self, value: Similarity) -> None:
        if not self._proxy:
            self._proxy = value
        else:
            msg = "The `proxy` attribute can only be initialized once."
            raise ProxyInitializationError(msg)

    def __getitem__(self, key: str) -> list[str]:
        return self.proxy[key]

    def __contains__(self, key: str) -> bool:
        raise NotImplementedError

    def __iadd__(self, value: str) -> Self:
        self.proxy += value
        return self

    def __iter__(self) -> str:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError


@dataclass(kw_only=True, slots=True)
class RetrieverAdapter(Similarity):
    """A lazy lookup that uses the Chroma vector store to perform similarity searches using OpenAI embeddings."""

    store: VectorStoreRetriever

    def __getitem__(self, key: str) -> list[str]:
        """Vectorizes key and performs similarity search returning a list of matching content."""
        return [doc.page_content for doc in self.store.invoke(key)]

    def __contains__(self, key: str) -> bool:
        """Vectorizes key and performs similarity search returning a boolean if there is at least one match."""
        raise NotImplementedError

    def __iadd__(self, value: str) -> Self:
        self.store.add_documents([Document(value)])
        return self

    def __iter__(self) -> str:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError

    def __str__(self) -> str:
        return f"RetrieverAdapter(search_type={self.store.search_type})"
