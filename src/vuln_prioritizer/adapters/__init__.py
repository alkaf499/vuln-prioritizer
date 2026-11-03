"""Source adapters: each turns a vendor store into ``list[Finding]``."""

from .navi import NaviSchemaError, load_findings

__all__ = ["NaviSchemaError", "load_findings"]
