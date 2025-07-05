from functools import partial
from unittest.mock import Mock

from langchain.vectorstores import VectorStore

from vulcan_core import Fact, RuleEngine, Similarity, action, condition
from vulcan_core.models import RetrieverAdapter

### Facts


class Foo(Fact):
    bar: bool = True
    biz: bool = False
    buz: bool = False


class Bar(Fact):
    baz: int = 0
    biff: str = ""


class AnotherFact(Fact):
    value: int = 23


class YetAnotherFact(Fact):
    value: str = ""


class MyLLMFact(Fact):
    chromosomes: str | None = None


class MyLLMSimilarity(Fact):
    lookup_attribute: Similarity


class MySummaryFact(Fact):
    value: bool = False


class MyNonPartialFact(Fact):
    value: int = 0
    another_attribute: int = 50


### Custom conditions


@condition
def my_cond() -> bool:
    return True


@condition
def another_cond() -> bool:
    return False


def setup_engine() -> RuleEngine:
    """Set up the engine with initial facts and rules that would generate the report.yml output"""
    engine = RuleEngine()

    vector_store = Mock(VectorStore)  # Mocking VectorStore for example purposes
    retriever = RetrieverAdapter(store=vector_store)

    # Starting facts
    engine.fact(Foo(bar=True, biz=False))
    engine.fact(AnotherFact(value=23))
    engine.fact(YetAnotherFact(value="foo"))
    engine.fact(MyLLMSimilarity(lookup_attribute=retriever))

    # Rule 1 - Based on starting facts, will fire `then` action during iteration 1
    engine.rule(
        name="Update biz if either bar or biz are True",
        when=condition(lambda: Foo.bar or Foo.biz),
        then=action(partial(Bar, baz=AnotherFact.value)),
    )

    # Rule 2 - Based on starting facts, will fire `inverse` action during iteration 1
    engine.rule(
        name="Update Bar if both bar and biz are True",
        when=condition(lambda: Foo.bar and Foo.biz),
        then=action(partial(Bar, baz=0, biff="some string")),
        inverse=action(partial(Bar, baz=24, biff=YetAnotherFact.value)),
    )

    # Rule 3 - Will be evalued `False` during iteration 1 but won't fire any action as `inverse` is not provided
    engine.rule(
        when=condition(lambda: Foo.biz),
        then=action(partial(Foo, buz=False)),
    )

    # Rule 4 - Will fire during iteration 2 because `Bar.baz` is set to `24` in Rule 2 during iteration 1
    engine.rule(
        name="Ask an LLM about chromosomes",
        when=~condition(f"Do humans have {Bar.baz} pairs of chromosomes?"),
        then=action(partial(MyLLMFact, chromosomes="This is a long string for use in examples.")),
    )

    # Rule 5 - This rule will fire during iteration 3 because Rule 4 added `MyLLMFact.chromosomes` during iteration 2, and we're assuming the Similarity search provides a value where the LLM will respond to the question with "true"
    engine.rule(
        name="Check if the LLM response is about an example",
        # when=condition(f"Does the content of {MyLLMFact.chromosomes} mention that it is an example?"),  # Use this version for actual testing, as the mock will fail
        when=condition(f"Does the content of {MyLLMFact.chromosomes} or {MyLLMSimilarity.lookup_attribute} mention that it is an example?"),
        then=action(partial(MySummaryFact, value=True)),
    )

    # Rule 6 - This rule will be evaluated during iteration 4 because `MySummaryFact` was added in Rule 5 during the iteration 3. However, it will not fire because the expressions will evaluate to `False`.
    engine.rule(
        when=~my_cond & another_cond | condition(lambda: not (MySummaryFact.value)),
        then=action(MyNonPartialFact(value=0, another_attribute=0)),
    )

    # Rule 7 - This rule will fire during iteration 4 because `MySummaryFact.value` is `True`
    engine.rule(
        when=condition(lambda: MySummaryFact.value),
        then=action(MyNonPartialFact(value=42, another_attribute=100)),
    )

    return engine


def run_example():
    """Run the example that would generate the report.yml output"""
    engine = setup_engine()
    engine.evaluate()
    return engine


if __name__ == "__main__":
    engine = run_example()
    print("Engine evaluation complete!")
    print(f"Final facts: {list(engine.facts.keys())}")
