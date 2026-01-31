<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Latchfield Technologies http://latchfield.com -->
<img alt="Vulcan Logo" src="https://latchfield.com/vulcan/assets/images/vulcan-logo.svg" height="100px">

# AI-Hybrid Rules Engine for Logical Reasoning
[![Version](https://img.shields.io/pypi/v/vulcan_core)](https://pypi.org/project/vulcan-core/)

Vulcan is an AI-hybrid rules engine designed for advanced automated reasoning. It combines the power of rule-based decision systems with LLMs (Large Language Models) for improved consistency and explainability in AI-powered systems.

Learn more about Vulcan at [https://latchfield.com/vulcan](https://latchfield.com/vulcan), or jump in with:

```bash
uv add vulcan-core
# or
poetry add vulcan-core
# or
pip install vulcan-core
```

To gain your bearings, read the documentation for guides and API reference: [https://latchfield.com/vulcan/docs](https://latchfield.com/vulcan/docs).

## Why use Vulcan?
Vulcan strives to improve AI reliability and explainability by explicitly separating computational logic from LLM prediction through declarative rules and microprompting. Vulcan provides developers with a toolkit to create, manage, and execute rules with seamless integration with LLMs and vector databases.

### Features:
* **AI-Hybrid Rules** - Combine deterministic logic with LLMs and vector databases
* **Transparent Decision-Making** - Full explainability of how decisions are made
* **Developer-Friendly API** - Intuitive interfaces for rule creation and management
* **Platform Flexibility** - Works across various environments and integrates with existing tools

### Simple Example:
Turn your lengthy unpredictable prompts:

> As a bakery, I want to buy 10 apples if I have less than 10 in inventory, but only if my supplier has apples used for baking in stock. Given I have 9 apples, and my supplier has "Honeycrisp", how many apples should I order?

Into repeatable, consistent, and explainable rules:

```python
# Use natural language for prediction and data retrieval:
engine.rule(
    when=condition(f"Are {Apple.kind} considered good for baking?"),
    then=action(Apple(baking=True)),
)

# Use computed logic for operations that must be correct:
engine.rule(
    when=condition(lambda: Apple.baking and Inventory.apples < 10),
    then=action(Order(apples=10)),
)

# Intelligent on-demand rule evaluation:
engine.fact(Inventory(apples=9))
engine.fact(Apple(kind="Honeycrisp"))
```

## Get Involved!
We welcome contributions from the community to help make Vulcan even better:

* **Contribute Code** - Check out the [contribution guidelines](https://github.com/latchfield/vulcan/blob/main/CONTRIBUTING.md) for information on how to submit pull requests
* **Report Issues** - Found a bug or have a feature request? Open an issue on our [GitHub repository](https://github.com/latchfield/vulcan-core/issues/)
* **Join the Community** - Connect with other Vulcan users and developers on [GitHub Discussions](https://github.com/latchfield/vulcan-core/discussions)

## Additional Resources
Learn more about Vulcan:

* [Core Concepts](https://latchfield.com/vulcan/docs/concepts) - Understand the fundamental principles of Vulcan
* [Guides & Tutorials](https://latchfield.com/vulcan/docs/guides/quick-start/) - Step-by-step instructions for common use cases
* [API Reference](https://latchfield.com/vulcan/docs/) - Detailed information about the Vulcan API
