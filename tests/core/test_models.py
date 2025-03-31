# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

import _string  # type: ignore
import inspect
import string
from dataclasses import dataclass, field

import pytest
from langchain.schema import Document
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings

from vulcan_core import Fact, Similarity
from vulcan_core.models import ProxyLazyLookup, RetrieverAdapter


# TODO: Do we need a dynamic/mutable fact type?
class NewsPaper(Fact):
    title: str
    locations: Similarity


@pytest.fixture
def chroma() -> RetrieverAdapter:
    values = ["New York", "Hawaii", "California", "Texas", "Florida", "Denmark"]
    documents = [Document(value) for value in values]

    # Create store
    store = Chroma(embedding_function=OpenAIEmbeddings(model="text-embedding-3-small"))
    retriever = store.as_retriever()
    retriever.add_documents(documents)

    return RetrieverAdapter(store=retriever)


@pytest.fixture
def newspaper(chroma: RetrieverAdapter) -> NewsPaper:
    return NewsPaper(title="The New York Times", locations=chroma)


@pytest.mark.integration
def test_retriever_adapter(chroma: RetrieverAdapter):
    assert chroma["Oil"][0] == "Texas"


@dataclass
class Bar:
    _parent: str = field(init=False, default="Unknown")
    _attr: str = field(init=False, default="unknown")

    @classmethod
    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        # Get the calling class name from the stack

        frame = inspect.currentframe()
        if frame:
            frame = frame.f_back

        if frame and "self" in frame.f_locals:
            caller = frame.f_locals["self"].__class__.__name__
            # Find the attribute name by inspecting the caller's annotations
            for name, typ in frame.f_locals["self"].__class__.__annotations__.items():
                if typ == Bar:
                    instance._parent = caller
                    instance._attr = name
                    break
        return instance

    def __str__(self):
        return f"{{{self._parent}.{self._attr}}}"


@dataclass
class Foo:
    bar: Bar = field(default_factory=Bar)


@dataclass
class Baz:
    buz: Bar = field(default_factory=Bar)


@dataclass
class Bizz:
    bears: Bar = field(default_factory=Bar)


def test_format():
    assert f"{Foo().bar}" == "{Foo.bar}"
    assert f"{Baz().buz}" == "{Baz.buz}"
    assert f"{Bizz().bears}" == "{Bizz.bears}"


class DeferredFormatter(string.Formatter):
    """Formatter that defers the evaluation of value searches."""

    def get_field(self, field_name, args, kwargs):
        first, rest = _string.formatter_field_name_split(field_name)
        obj = self.get_value(first, args, kwargs)
        if isinstance(obj, Similarity):
            return (f"{{{field_name}}}", field_name)
        else:
            for is_attr, i in rest:
                obj = getattr(obj, i) if is_attr else obj[i]
            return obj, first


def test_format2():
    d = {"a": 1, "b": ProxyLazyLookup()}
    s = "{a} {b.c}"
    DeferredFormatter().vformat(s, [], d)
