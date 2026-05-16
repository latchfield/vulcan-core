# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Latchfield Technologies http://latchfield.com

import functools
from collections.abc import Awaitable, Callable, Iterator
from contextlib import AbstractContextManager
from contextvars import copy_context
from dataclasses import dataclass
from functools import wraps
from typing import Any, NoReturn

import greenlet


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


class AttrDict(dict[str, Any]):
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

    def __contains__(self, key: str) -> bool:  # ty:ignore[invalid-method-override] - base class is constrained to str keys
        return hasattr(self, self.validate(key))

    def __or__(self, other: dict) -> dict:
        return dict(self) | other

    def __repr__(self) -> str:
        return repr(dict(self))

    def keys(self) -> list[str]:  # ty:ignore[invalid-method-override] - base class is constrained to str keys
        return list(self)

    def values(self) -> list[Any]:  # ty:ignore[invalid-method-override] - base class is constrained to str keys
        return [getattr(self, key) for key in self]

    def items(self) -> list[tuple[str, Any]]:  # ty:ignore[invalid-method-override] - base class is constrained to str keys
        return [(key, getattr(self, key)) for key in self]

    def get(self, key: str, default: Any = None):
        return getattr(self, self.validate(key), default)

    def setdefault(self, key: str, default: Any = None) -> Any:
        if key not in self:
            self[key] = default
        return self[key]

    @not_implemented
    def __delitem__(self, key: str) -> NoReturn: ...  # ty:ignore[empty-body] - ty is unware of the not_implemented decorator

    @not_implemented
    def __ior__(self, other: dict[str, Any]) -> NoReturn: ...  # ty:ignore[empty-body] - ty is unware of the not_implemented decorator

    @not_implemented
    def clear(self) -> NoReturn: ...  # ty:ignore[empty-body] - ty is unware of the not_implemented decorator

    @not_implemented
    def copy(self) -> NoReturn: ...  # ty:ignore[empty-body] - ty is unware of the not_implemented decorator

    @not_implemented
    def pop(self, key: str, defaul: Any = None) -> NoReturn: ...  # ty:ignore[empty-body] - ty is unware of the not_implemented decorator

    @not_implemented
    def popitem(self) -> NoReturn: ...  # ty:ignore[empty-body] - ty is unware of the not_implemented decorator

    @not_implemented
    def update(self, *args, **kwargs) -> NoReturn: ...  # ty:ignore[empty-body] - ty is unware of the not_implemented decorator


async def gcall[T, **P](fn: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    """Execute a synchronous function with support for nested async operations.

    Enables async_or_sync() calls within the synchronous function to properly await coroutines by switching execution
    contexts. The function runs to completion with any async operations handled in the calling async context.

    Args:
        fn: Synchronous function to execute.
        *args: Positional arguments forwarded to `fn`.
        **kwargs: Keyword arguments forwarded to `fn`.

    Returns:
        Result of executing `fn` with the provided arguments.
    """
    result_holder: list[T] = []
    ctx = copy_context()

    def runner() -> None:
        result_holder.append(ctx.run(fn, *args, **kwargs))

    gr = greenlet.greenlet(runner)
    gr.gr_context = greenlet.getcurrent().gr_context
    value: Awaitable[Any] = gr.switch()
    while not gr.dead:
        result = await value
        value = gr.switch(result)

    return result_holder[0]


def async_or_sync[T](*, await_on: Callable[[], Awaitable[T]], or_call: Callable[[], T] | None = None) -> T:
    """Return the result of await_on in async context or or_call in sync context.

    Both callables are lazy, so only the chosen branch is invoked and the other is never executed unnecessarily. Requires
    that the caller is either running in a greenlet (async context, via gcall) or a normal thread (sync context).

    Args:
        await_on: Callable returning an awaitable, invoked when running inside a greenlet.
        or_call: Callable returning the result directly, invoked on the plain sync path.

    Returns:
        The result of the chosen strategy.
    """
    if greenlet.getcurrent().parent is not None:
        current = greenlet.getcurrent()
        return current.parent.switch(await_on())

    if or_call is None:
        msg = "or_call must be provided when in synchronous context."
        raise NotImplementedError(msg)

    return or_call()
