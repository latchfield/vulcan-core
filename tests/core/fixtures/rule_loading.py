from functools import partial

from vulcan_core import Fact, RuleEngine, action, condition


class Foo(Fact):
    baz: bool = True
    bol: bool = True


def load_simple_rule(engine: RuleEngine):
    # This rule tests for repeated parsing of the same lambda expression, plus potential errors with naive parsing.
    engine.rule(
        name="test_rule",
        when=condition(lambda: Foo.baz and "lambda:" != None),  # Keep this comment to test parser counting: lambda:
        then=action(partial(Foo, bol=False)),
    )
