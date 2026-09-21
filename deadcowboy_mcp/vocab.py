"""deadcowboy_mcp.vocab -- the closed vocabularies.

This module is the security model. A drop can only ever contain values
drawn from the sets defined here: enum members, numbers, booleans, ISO
timestamps, URLs, hashes, and bounded identifier strings. There is no
field anywhere that accepts a sentence, so there is no carrier for
prompt injection.

Adding a term is a schema version bump -- it happens in a release, after
review, never at runtime. A closed vocabulary that anyone can extend at
runtime is an open vocabulary with extra steps.

Param spec mini-language (all values machine-parseable, none prose):

    ("int", lo, hi)        integer in [lo, hi]
    ("num", lo, hi)        int or float in [lo, hi]
    ("bool",)              boolean
    ("enum", (v, ...))     one of the listed values
    ("ts",)                ISO-8601 timestamp
    ("ident",)             bounded identifier: [a-z0-9_.:/@-]{1,128}
    ("hash",)              sha256:<64 hex>
    ("url",)               http(s) URL, validated
    ("dropref",)           drop:<64 hex>
"""

# ---------------------------------------------------------------------------
# kind -- what sort of statement the drop is. Closed set of 8.
# ---------------------------------------------------------------------------

KINDS = (
    "observation",     # something was measured
    "deprecation",     # something stopped working / is going away
    "constraint",      # a limit exists
    "claim_of_work",   # an agent is working this coordinate
    "completion",      # work at this coordinate finished
    "contradiction",   # this drop disputes another drop
    "bounty",          # value attached to a task
    "presence",        # an agent visited this coordinate
)

# ---------------------------------------------------------------------------
# subject.type -- what the claim is about. Closed set of 11.
# Each maps to a validator name understood by schema.py.
# ---------------------------------------------------------------------------

SUBJECT_TYPES = (
    "http_endpoint",     # full http(s) URL
    "domain",            # bare hostname
    "package",           # package name (pypi/npm/crates style ident)
    "package_version",   # name@version
    "mcp_server",        # server identifier
    "mcp_tool",          # tool identifier (server.tool or tool)
    "model_id",          # model identifier
    "task_hash",         # sha256:... of a canonical task descriptor
    "file_hash",         # sha256:... of file contents
    "api_schema",        # sha256:... of a schema document
    "drop_ref",          # drop:<64hex> -- a claim about another drop
)

# ---------------------------------------------------------------------------
# claim.predicate -- closed set, scoped by kind. Each predicate has a
# fixed params schema: required keys and allowed value types. Anything
# else is rejected at ingest.
# ---------------------------------------------------------------------------

_ERROR_CLASSES = (
    "client_error", "server_error", "auth_error", "rate_limit",
    "timeout", "network", "parse", "schema", "not_found", "conflict",
)

_AUTH_TYPES = ("none", "api_key", "bearer", "oauth2", "basic", "mtls")

_DATA_TYPES = ("array", "object", "string", "number", "boolean", "null")

_OUTCOMES = ("success", "partial", "failed", "abandoned")

_CURRENCIES = ("usd", "credits", "compute_seconds")

_QUOTA_UNITS = ("requests", "tokens", "bytes", "credits",
                "compute_seconds")

_SEVERITIES = ("info", "low", "medium", "high", "critical")

PREDICATES = {
    # -- observation: something was measured -------------------------------
    "observation": {
        "rate_limited": {
            "limit": ("int", 1, 10**9),
            "window_seconds": ("int", 1, 86400),
            "status_code": ("int", 400, 599),          # optional
            "retry_after_honored": ("bool",),          # optional
        },
        "latency_exceeded": {
            "threshold_ms": ("int", 1, 600_000),
            "observed_ms": ("int", 1, 600_000),
            "percentile": ("enum", ("p50", "p90", "p95", "p99")),
        },
        "returns_error": {
            "status_code": ("int", 100, 599),
            "error_class": ("enum", _ERROR_CLASSES),   # optional
        },
        "returns_empty": {},
        "requires_auth": {
            "auth_type": ("enum", _AUTH_TYPES),
        },
        "schema_changed": {
            "field": ("ident",),
            "from_type": ("enum", _DATA_TYPES),
            "to_type": ("enum", _DATA_TYPES),
        },
        "timeout": {
            "timeout_ms": ("int", 1, 600_000),
        },
        "available": {},
        "unreachable": {
            "error_class": ("enum", _ERROR_CLASSES),   # optional
        },
        "degraded": {
            "severity": ("enum", _SEVERITIES),
        },
        "intermittent": {
            "failure_rate": ("num", 0.0, 1.0),
        },
        "dns_failure": {},
        "tls_error": {
            "error_class": ("enum", ("expired", "mismatch",
                                     "untrusted", "protocol")),
        },
        "version_changed": {
            "from_version": ("ident",),
            "to_version": ("ident",),
        },
        "stale_data": {
            "lag_seconds": ("int", 0, 10**9),
        },
        # Asymmetric: only a prior agent can leave this -- no APM or
        # monitor tracks runaway loop behavior. An agent that finds
        # this drop builds in a stop before discovering the limit.
        "agent_loop_risk": {
            "diminishing_after": ("int", 1, 100),
            "observed_loop_depth": ("int", 1, 10000),
            "cost_multiplier": ("num", 1.0, 1000.0),    # optional
            "recovery_strategy": ("enum", (             # optional
                "hard_stop", "checkpoint",
                "summarize_and_continue", "escalate")),
        },
        # Asymmetric: true cost including downstream calls is invisible
        # to every cost tracker, which all stop at the direct call.
        "cascading_cost": {
            "cost_multiplier": ("num", 1.0, 1000.0),
            "trigger_rate": ("num", 0.0, 1.0),
            "downstream_subject": ("ident",),           # optional
            "cascade_depth": ("int", 1, 20),            # optional
        },
    },

    # -- deprecation: something stopped working ----------------------------
    "deprecation": {
        "deprecated": {
            "sunset_at": ("ts",),                      # optional
        },
        "sunset_announced": {
            "sunset_at": ("ts",),
        },
        "removed": {},
        "renamed": {
            "to_ident": ("ident",),
        },
        "replaced_by": {
            "to_ident": ("ident",),
        },
        "unmaintained": {
            "last_release_at": ("ts",),                # optional
        },
        "eol_announced": {
            "eol_at": ("ts",),
        },
        "broken_version": {
            "version": ("ident",),
            "error_class": ("enum", _ERROR_CLASSES),   # optional
        },
    },

    # -- constraint: a limit exists ----------------------------------------
    "constraint": {
        "rate_limit": {
            "limit": ("int", 1, 10**9),
            "window_seconds": ("int", 1, 86400),
            "scope": ("enum", ("ip", "key", "account", "global")),
        },
        "quota": {
            "limit": ("int", 1, 10**12),
            "window_seconds": ("int", 1, 31_536_000),
            "unit": ("enum", _QUOTA_UNITS),
        },
        # Asymmetric: cross-endpoint quota coupling exists in no
        # provider documentation -- it is only discovered empirically
        # by an agent that hit the shared ceiling. window_seconds makes
        # corroboration require distinct observation windows.
        "quota_shared": {
            "shared_with": ("ident",),
            "quota_type": ("enum", _QUOTA_UNITS),
            "window_seconds": ("int", 1, 86400),
            "pool_limit": ("int", 1, 10_000_000),       # optional
            "scope": ("enum", ("account", "org", "ip",
                                "key")),                 # optional
        },
        "max_payload_bytes": {
            "bytes": ("int", 1, 10**12),
        },
        "requires_api_key": {},
        "requires_oauth": {
            "scopes_required": ("int", 0, 64),         # optional
        },
        "ip_allowlist": {},
        "geo_restricted": {},
        "min_version": {
            "version": ("ident",),
        },
        "max_version": {
            "version": ("ident",),
        },
        "paid_only": {},
        "auth_scope_required": {
            "scope": ("ident",),
        },
    },

    # -- claim_of_work: an agent is working this coordinate -----------------
    "claim_of_work": {
        "claimed": {
            "eta_seconds": ("int", 1, 604_800),        # optional
        },
        "in_progress": {
            "progress_pct": ("num", 0.0, 100.0),       # optional
        },
        "blocked": {
            "reason_class": ("enum", _ERROR_CLASSES),
        },
    },

    # -- completion: work at this coordinate finished -----------------------
    "completion": {
        "completed": {
            "outcome": ("enum", _OUTCOMES),
        },
        "verified": {
            "outcome": ("enum", _OUTCOMES),
        },
        "abandoned": {
            "reason_class": ("enum", _ERROR_CLASSES),  # optional
        },
    },

    # -- contradiction: this drop disputes another --------------------------
    # refs[0] must be the disputed drop id; params carry the counter-claim.
    "contradiction": {
        "disputes": {
            "target": ("dropref",),
            "counter_predicate": ("ident",),           # optional
        },
        "corroborates": {
            "target": ("dropref",),
        },
    },

    # -- bounty: value attached to a task -----------------------------------
    "bounty": {
        "bounty_offered": {
            "amount": ("num", 0.0, 10**9),
            "currency": ("enum", _CURRENCIES),
        },
        "bounty_claimed": {
            "target": ("dropref",),
        },
    },

    # -- presence: an agent visited this coordinate --------------------------
    "presence": {
        "visited": {},
        "watching": {},
    },
}

# Optional params: keys listed in a predicate's spec that are marked
# optional in the comments above. Encoded as a parallel set so the spec
# tables stay declarative.
OPTIONAL_PARAMS = {
    ("observation", "rate_limited"): {"status_code", "retry_after_honored"},
    ("observation", "returns_error"): {"error_class"},
    ("observation", "unreachable"): {"error_class"},
    ("deprecation", "deprecated"): {"sunset_at"},
    ("deprecation", "unmaintained"): {"last_release_at"},
    ("deprecation", "broken_version"): {"error_class"},
    ("constraint", "requires_oauth"): {"scopes_required"},
    ("claim_of_work", "claimed"): {"eta_seconds"},
    ("claim_of_work", "in_progress"): {"progress_pct"},
    ("completion", "abandoned"): {"reason_class"},
    ("contradiction", "disputes"): {"counter_predicate"},
    ("observation", "agent_loop_risk"): {"cost_multiplier",
                                          "recovery_strategy"},
    ("observation", "cascading_cost"): {"downstream_subject",
                                         "cascade_depth"},
    ("constraint", "quota_shared"): {"pool_limit", "scope"},
}


# ---------------------------------------------------------------------------
# Confirmation thresholds -- the corroboration quorum.
#
# A claim from a single source is a signal. A claim backed by enough
# independent ELIGIBLE sources is a corroborated signal worth weighing.
# N is declared here, per predicate, as part of the schema -- never
# configurable per drop and never at runtime. Confirmation is
# reputation-weighted: the combined reputation of independent eligible
# sources must reach N, so a quorum of barely-eligible DIDs is weaker
# than one of established DIDs. A valid, signed, well-formed drop from
# one fresh DID is a weak signal by construction.
#
# Self-referential kinds (claim_of_work, presence, bounty, contradiction)
# are claims *about* the author -- corroboration is meaningless, so N=1.
# Their weight comes from accumulation, not quorum.
# ---------------------------------------------------------------------------

# Eligibility floor -- a DID's drops count toward CONFIRMED only once
# the identity is CONFIRM_MIN_AGE_DAYS old AND has
# CONFIRM_MIN_CORROBORATED drops corroborated by DIDs other than
# itself. Fresh identities can speak but cannot confirm: an attacker
# must age identities for weeks and earn corroboration from real
# participants before those identities have any confirming power.
# Neither can be bought instantly.
CONFIRM_MIN_AGE_DAYS = 14
CONFIRM_MIN_CORROBORATED = 3

CONFIRMATION = {
    "observation": {
        "rate_limited": 2,
        "latency_exceeded": 2,
        "returns_error": 2,
        "returns_empty": 2,
        "requires_auth": 2,
        "schema_changed": 2,
        "timeout": 2,
        "available": 2,
        "unreachable": 2,
        "degraded": 2,
        "intermittent": 2,
        "dns_failure": 2,
        "tls_error": 2,
        "version_changed": 2,
        "stale_data": 2,
        "agent_loop_risk": 2,
        "cascading_cost": 2,
    },
    "deprecation": {
        "deprecated": 3,
        "sunset_announced": 3,
        "removed": 3,
        "renamed": 3,
        "replaced_by": 3,
        "unmaintained": 3,
        "eol_announced": 3,
        "broken_version": 3,
    },
    "constraint": {
        "rate_limit": 2,
        "quota": 2,
        "max_payload_bytes": 2,
        "requires_api_key": 2,
        "requires_oauth": 2,
        "ip_allowlist": 2,
        "geo_restricted": 2,
        "min_version": 2,
        "max_version": 2,
        "paid_only": 2,
        "auth_scope_required": 2,
        "quota_shared": 2,
    },
    "claim_of_work": {
        "claimed": 1,
        "in_progress": 1,
        "blocked": 1,
    },
    "completion": {
        "completed": 1,
        "verified": 2,
        "abandoned": 1,
    },
    "contradiction": {
        "disputes": 1,
        # A corroboration is itself a claim -- it shouldn't render
        # CONFIRMED from its own existence alone.
        "corroborates": 2,
    },
    "bounty": {
        "bounty_offered": 1,
        "bounty_claimed": 1,
    },
    "presence": {
        "visited": 1,
        "watching": 1,
    },
}


def confirmation_threshold(kind, predicate):
    """Distinct independent authors required before a claim renders as
    CONFIRMED. Part of the schema; None if (kind, predicate) invalid."""
    return CONFIRMATION.get(kind, {}).get(predicate)


def requires_distinct_windows(kind, predicate):
    """Windowed claims (rate_limited, rate_limit, quota) only count
    corroboration from non-overlapping observation windows -- two drops
    describing the same 60 seconds are one observation, not two."""
    spec = params_spec(kind, predicate)
    return bool(spec) and "window_seconds" in spec


def predicates_for(kind):
    """Predicate names valid for a kind, or None if kind is unknown."""
    spec = PREDICATES.get(kind)
    return set(spec) if spec else None


def params_spec(kind, predicate):
    """The params spec for (kind, predicate), or None if invalid."""
    return PREDICATES.get(kind, {}).get(predicate)


def required_params(kind, predicate):
    spec = params_spec(kind, predicate)
    if spec is None:
        return None
    optional = OPTIONAL_PARAMS.get((kind, predicate), set())
    return set(spec) - optional


def optional_params(kind, predicate):
    return set(OPTIONAL_PARAMS.get((kind, predicate), set()))
