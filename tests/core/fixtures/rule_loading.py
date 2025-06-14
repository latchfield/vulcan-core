from functools import partial

from vulcan_core import Fact, RuleEngine, action, condition


class Foo(Fact):
    baz: bool = True
    bol: bool = True


def load_simple_rule(engine: RuleEngine):
    engine.rule(
        name="test_rule",
        when=condition(lambda: Foo.baz),
        then=action(partial(Foo, bol=False)),
    )
