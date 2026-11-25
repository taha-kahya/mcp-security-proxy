"""Startup wiring for the security half of the proxy: policy with defense
enforcement, the defense execution plan, tool semantics, Scan, state, and
the `ProxyControl` that combines them.

Everything that can be validated without upstream servers is checked in
`load_security`, before any subprocess is spawned.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from mcp_security_proxy.app.config import ClassifierConfig, ProxyConfig, StateConfig
from mcp_security_proxy.app.defenses import load_defense_configs
from mcp_security_proxy.core.guard import Guard
from mcp_security_proxy.core.identity import PrincipalTaskResolver
from mcp_security_proxy.core.proxy.control import ProxyControl
from mcp_security_proxy.core.proxy.routing.table import RoutingTable
from mcp_security_proxy.core.runner import (
    ContextFactory,
    DefenseCatalog,
    DefenseSpec,
    ExecutionPlan,
    Runner,
    build_plan,
)
from mcp_security_proxy.sdk import Capability
from mcp_security_proxy.services.history import History
from mcp_security_proxy.services.policy import PolicySnapshot, load_policy
from mcp_security_proxy.services.registry import (
    ConfiguredToolAdapter,
    Registry,
    ToolSemanticsError,
    load_tool_semantics,
)
from mcp_security_proxy.services.scan import RuleScanner, Scan
from mcp_security_proxy.services.scan.classifier import (
    DefinitionClassifier,
    OperatingPoint,
    load_classifier,
)
from mcp_security_proxy.services.state import (
    DefenseStateStore,
    InMemoryStateStore,
    SqliteStateStore,
    StateStore,
)

logger = logging.getLogger(__name__)

# Every capability the SDK defines is provided by the core; the classifier
# stage only when `scan.classifier` is configured. A defense that needs it
# would otherwise hide every tool, which an evaluation could misread as
# blocking, so the plan refuses it at startup (ADR 0026).
AVAILABLE_CAPABILITIES = frozenset(Capability)


@dataclass(frozen=True)
class SecuritySetup:
    policy: PolicySnapshot
    plan: ExecutionPlan
    tool_semantics: ConfiguredToolAdapter
    defense_deadline_seconds: float
    scan: Scan


def load_security(config: ProxyConfig, catalog: DefenseCatalog) -> SecuritySetup:
    configs = load_defense_configs(config.defenses_path)
    enabled = [c for c in configs if c.enabled]
    overrides = {c.id: c.enforcement for c in enabled if c.enforcement is not None}
    enabled_ids = {c.id for c in enabled}
    known_ids = {c.id for c in configs} | set(catalog.names())
    policy = load_policy(
        config.policy_path,
        overrides,
        defense_ids=enabled_ids,
        disabled_defense_ids=known_ids - enabled_ids,
    )
    _warn_about_loosened_enforcement(policy)
    available = AVAILABLE_CAPABILITIES
    if config.scan.classifier is None:
        available -= {Capability.SCAN_CLASSIFIER}
    plan = build_plan([DefenseSpec(c.id, c.settings) for c in enabled], catalog, available)
    logger.info("enabled defenses: %s", ", ".join(plan.defense_ids()) or "none")
    semantics = (
        load_tool_semantics(config.tools_path)
        if config.tools_path is not None
        else ConfiguredToolAdapter.empty()
    )
    # Built here so its Unicode data, and the model if a defense needs it,
    # load before any upstream server starts.
    scan = Scan(RuleScanner(), _load_classifier(config.scan.classifier, plan))
    return SecuritySetup(policy, plan, semantics, config.defense_deadline_seconds, scan)


def _load_classifier(
    config: ClassifierConfig | None, plan: ExecutionPlan
) -> DefinitionClassifier | None:
    if config is None:
        return None
    if not plan.requires(Capability.SCAN_CLASSIFIER):
        logger.warning(
            "scan.classifier is configured but no enabled defense requires %s; "
            "the model is not loaded",
            Capability.SCAN_CLASSIFIER,
        )
        return None
    classifier = load_classifier(
        config.model_dir,
        OperatingPoint(config.operating_point),
        device=config.device,
        token_budget=config.token_budget,
        cache_entries=config.cache_entries,
        timeout=config.timeout_seconds,
    )
    logger.info("scan classifier stage: %s", classifier.version)
    return classifier


def open_state(config: StateConfig) -> StateStore:
    if config.backend == "sqlite":
        if config.path is None:
            raise RuntimeError("sqlite state backend configured without a path")
        return SqliteStateStore.open(config.path)
    return InMemoryStateStore()


def build_registry(routing_table: RoutingTable, semantics: ConfiguredToolAdapter) -> Registry:
    registry = Registry(semantics)
    for routed in routing_table.entries():
        # The raw object, when kept (transparent mode), is exactly what the
        # agent receives, so defenses and the version digest must cover it,
        # unknown fields included. The typed tool drops those.
        definition = (
            routed.raw
            if routed.raw is not None
            else routed.tool.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
        registry.register(routed.tool_id, definition)
    unmatched = semantics.unmatched(registry.tool_ids())
    if unmatched:
        names = ", ".join(str(tool_id) for tool_id in unmatched)
        raise ToolSemanticsError(f"tool semantics name no discovered tool: {names}")
    return registry


def build_control(
    setup: SecuritySetup, registry: Registry, history: History, state: StateStore
) -> ProxyControl:
    defense_state = DefenseStateStore(state)
    runner = Runner(
        setup.plan,
        ContextFactory(defense_state, setup.scan),
        deadline_seconds=setup.defense_deadline_seconds,
    )
    return ProxyControl(
        policy=setup.policy,
        tasks=PrincipalTaskResolver(),
        registry=registry,
        history=history,
        defense_state=defense_state,
        runner=runner,
        guard=Guard(),
        prescan=setup.scan,
    )


def _warn_about_loosened_enforcement(policy: PolicySnapshot) -> None:
    for defense_id, loosened in policy.enforcement.loosened_overrides().items():
        logger.warning("defense %r loosens enforcement: %s", defense_id, "; ".join(loosened))
