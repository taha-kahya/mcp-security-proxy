# Server identity and the registration defense

This note supports [ADR 0022](../decisions/0022-server-identity-view-and-registration-defense.md). It
sketches the contract and the rules, and states how the defense is evaluated. It is a proposal for
review, not an implemented design.

## The attack, in the taxonomy's words

In **malicious server registration** the attacker controls an entire MCP server that the host connects
to next to trusted ones. The attacker uses what the server declares about itself, its reported name and
its tool metadata, to make the agent prefer it or send it data. The server does nothing the
protocol forbids; it only claims things.

## Where it fits

| Question | Answer |
| --- | --- |
| Category | Environment (architecture §V4; ADR 0021, capability 4) |
| Stage | `discovery`, after the server's `InitializeResult` and tool list are known |
| Capabilities | `servers` (new), `registry` |
| Produces | findings only; no signals in this version |
| Enforcement | the operator's policy, as for every defense (ADR 0018) |

## Contract sketch

```python
@dataclass(frozen=True)
class ServerRecord:
    server_id: str            # operator config; authoritative
    transport: str            # "stdio" | "streamable_http"
    launch: str               # command line or URL without credentials; authoritative
    approved: bool            # an operator entry matches server_id and launch
    reported_name: str        # CLAIM, from InitializeResult
    reported_version: str     # CLAIM
    tool_ids: tuple[str, ...]

class ServersView(Protocol):
    def all(self) -> tuple[ServerRecord, ...]: ...
    def get(self, server_id: str) -> ServerRecord | None: ...
```

The view has no tool content and no secrets. A defense that wants definitions uses `registry`.

## Rules, each with a matched benign twin

The cases below are written from the taxonomy, not from any experiment.

| Rule | Malicious case | Benign twin |
| --- | --- | --- |
| `.unregistered_server` | a server connected without an operator entry | the same server with an entry and a matching pin |
| `.lookalike_name` | a server reports the name of an approved server with one letter swapped for a visually similar character | two servers with unrelated names |
| `.lookalike_name` | a tool named like an approved server's tool after case folding and punctuation removal | a tool with an unrelated name |
| `.capability_overlap` | an unapproved server offers a tool with an approved tool's name and input-schema shape | a unique tool |
| `.identity_changed` | an approved `server_id` is relaunched with a different command, or reports a different name | the same record on re-discovery |

Each rule needs these other cases, as in the add-defense checklist: events at other stages are
`not_applicable`; a missing `servers` view is `unsupported`, not `completed`; invalid settings raise
`ValueError`.

## Settings with safe defaults

- `max_edit_distance` (default 2) and `min_name_length` (default 5) for lookalike detection;
  shorter names compare only by exact normalized equality.
- `confusables` on by default (Unicode normalization before comparison).
- No setting turns off `.unregistered_server`.

## What it does not cover

- **A semantically similar name.** A server named differently but implying the same role is not
  detected. `.capability_overlap` catches only matching tool names or schema shapes.
- **Where data goes next.** Whether content from one server is sent to another needs argument-aware
  tool adapters (Cross-tool, ADR 0021 capability 2).
- **A trusted server that changes behaviour.** Temporal category.
- **An approved server that is itself malicious.** Out of scope; approval is the operator's trust.

## Evaluation

The research repository holds an experiment for this attack, run without a proxy. It is the held-out
evaluation, so none of its texts, prompts, fixtures or results are used to design or test the defense.
It is rerun with the experiment's own protocol structure in three arms, each with its own frozen
protocol:

1. **No proxy:** the recorded cohort, cited as recorded.
2. **Pass-through:** the proxy with no defenses, so the proxy's own effect (for example disambiguated
   tool names) is separated from the defense's.
3. **Defended:** the proxy with `environment_server_registration` and the shipped policy.

The measures are the attack outcome from the upstream servers' own audit logs, what the agent was
shown, false findings on clean and authorized-control runs, task completion, and added latency. The
research repository's agent-side defenses (registry-style filtering and a data-flow check) are agent
safeguards, not proxy enforcement, and their results are not proxy results.
