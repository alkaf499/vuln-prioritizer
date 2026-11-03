"""OPTIONAL LLM asset classifier ("Layer B") - drafts a CMDB overlay for assets no human rule covers.

THE DETERMINISM FIREWALL
------------------------
Nothing in ``scoring/``, ``pipeline``, ``worklist``, ``report`` (or anything else on the ``run``
path) imports this package, and ``run`` never calls it. The classifier's only product is a
*file*: ``out/classification.ai.yaml``, in the ordinary overlay format. A human reviews it and
passes it explicitly as a later ``--overlay``; the pipeline reads it like any other overlay file
and cannot tell who wrote it. Same frozen overlays -> same worklist, byte for byte. The test
suite enforces the import boundary (``tests/test_classifier_firewall.py``).

TRUST MODEL
-----------
* Hostnames / OS strings are DATA, never instructions. They reach the model as JSON values
  under a system prompt that says so, and nothing the model returns is trusted: every field is
  validated against the existing enums in ``context.model`` (exact values only - no aliases) and
  a closed role list; anything else abstains.
* A name is a *claim*, not evidence: high-privilege results (external exposure, any non-standard
  criticality) need a higher confidence than ordinary ones, else the asset abstains.
* Abstain = no rule is written, so the asset stays ``unknown`` and flagged for re-evaluation.
  The classifier never emits ``in_scope`` (it cannot exclude an asset) and never fabricates a
  crown jewel.
* The generated overlay is tenant-derived. Keep it under the gitignored ``out/``; never commit.

Modules: ``validate`` (strict parsing + policy), ``llm`` (stdlib ``urllib`` Messages API client,
key from ``ANTHROPIC_API_KEY`` only), ``cache`` (resumable, keyed by hostname + OS), ``engine``
(batching), ``render`` (overlay YAML writer), ``cli`` (the ``classify`` subcommand).

Stdlib only: no new dependency.
"""
