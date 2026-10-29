"""Public contracts shared by core modules, services, and defenses.

Depends on nothing else in this package, so defenses can be written against
it alone and every other module can import it without depending on core or
service implementations. `mcp_security_proxy.sdk.testing` holds test helpers
and is not imported here.
"""

from mcp_security_proxy.sdk.actions import Action, Operation, Sensitivity
from mcp_security_proxy.sdk.capabilities import (
    ABSENT,
    HistorySnapshot,
    OperationRecord,
    OperationStatus,
    PolicyView,
    PrivateState,
    RegistryView,
    ToolDefinition,
    VersionedValue,
)
from mcp_security_proxy.sdk.context import CapabilityNotGrantedError, Context, Grants
from mcp_security_proxy.sdk.defense import DEFENSE_ENTRY_POINT_GROUP, Defense, DefenseFactory
from mcp_security_proxy.sdk.digest import canonical_digest
from mcp_security_proxy.sdk.events import (
    ContentBlock,
    ContentSource,
    Direction,
    Event,
    Provenance,
    Stage,
)
from mcp_security_proxy.sdk.frozen import freeze, thaw
from mcp_security_proxy.sdk.manifest import Capability, Manifest
from mcp_security_proxy.sdk.results import (
    Finding,
    InspectionStatus,
    Result,
    Severity,
    Signal,
    StateChange,
)
from mcp_security_proxy.sdk.types import Principal, ToolId
from mcp_security_proxy.sdk.version import CONTRACT_VERSION, SDK_VERSION

__all__ = [
    "ABSENT",
    "CONTRACT_VERSION",
    "DEFENSE_ENTRY_POINT_GROUP",
    "SDK_VERSION",
    "Action",
    "Capability",
    "CapabilityNotGrantedError",
    "ContentBlock",
    "ContentSource",
    "Context",
    "Defense",
    "DefenseFactory",
    "Direction",
    "Event",
    "Finding",
    "Grants",
    "HistorySnapshot",
    "InspectionStatus",
    "Manifest",
    "Operation",
    "OperationRecord",
    "OperationStatus",
    "PolicyView",
    "Principal",
    "PrivateState",
    "Provenance",
    "RegistryView",
    "Result",
    "Sensitivity",
    "Severity",
    "Signal",
    "Stage",
    "StateChange",
    "ToolDefinition",
    "ToolId",
    "VersionedValue",
    "canonical_digest",
    "freeze",
    "thaw",
]
