"""Framework adapters.

Each adapter is a thin translation layer between a framework's tool-call
representation and Doorman's ``ToolCall``/``Verdict``. Adapters never add
policy of their own — the ``Guard`` decides, the adapter only speaks the
framework's dialect.

Import the submodule you need; adapters are not imported here so the package
stays dependency-free.
"""
