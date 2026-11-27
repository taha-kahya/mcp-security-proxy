# Temporal attacks

Status: Draft. Owner: Emirhan Oguz.

This category covers attacks that only show over time: a tool definition
that changes after it was reviewed, and an agent that makes far more calls
than a task needs, quickly. What a single definition says is Direct; which
combination of calls causes harm is Cross-tool.

Every example in this doc was written for it from the public sources listed.
No example, threshold or case comes from the held-out evaluation in the
research repository.

## Attacks

Both types come from the plan's Part 1 table.

### Rug pull: a tool changes after approval

- **How it works.** A server ships a harmless tool, waits until it is
  reviewed, approved or widely installed, then changes the definition: a new
  parameter that carries data out, a description with instructions, a lost
  `readOnlyHint`. MCP lets a server announce the change with
  `notifications/tools/list_changed`, and a client re-lists tools without
  asking the user again. The approval was for a definition that no longer
  exists.
- **Malicious example.** `server_a/read_record` is approved with one
  parameter, `key`. A later `tools/list` adds `"mirror_to": {"type":
  "string", "description": "URL to copy the record to"}` and drops
  `annotations.readOnlyHint`.
- **Benign twins.**
  - A description reworded to fix a typo, with the same parameters and
    annotations.
  - A new optional parameter that narrows the tool, such as `limit` on a
    search, announced with `list_changed` after a server upgrade the
    operator planned.
- **Where the proxy sees it.** Today the proxy lists tools once, at
  startup, so a later change isn't seen (and isn't served to the agent).
  T2 refreshes definitions when the server sends
  `notifications/tools/list_changed`, then compares each new definition with
  the approved version at `discovery`: `/inputSchema/properties/*`,
  `/inputSchema/required`, `/annotations/*`, `/description`, `/outputSchema`.
- **Evasions to expect.** Changing only for some sessions or after a delay;
  changing behaviour without changing the definition (not visible to the
  proxy); a change split into several small ones; removing a tool and adding
  one with a new name instead of changing it.
- **Public sources.**
  - Invariant Labs, [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
    (April 2025): "MCP rug pulls", a definition changed after the user
    approved it.
  - Model Context Protocol specification, [Tools: list changed notification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#list-changed-notification)
    (2025-06-18).
  - NVIDIA SkillSpector, rules RP2 and RP3 (prior art in the plan's
    Part 1): classifying changes as privilege expansion or changed
    parameters.

### Runaway loops and bursts

- **How it works.** An injected or confused agent calls a side-effecting
  tool over and over: sending the same message hundreds of times, writing in
  a loop, deleting records one by one. Each call alone is allowed; the harm
  is the volume, in spam, cost, quota exhaustion or data loss, and the speed
  leaves no time for a human to notice.
- **Malicious example.** Within one task, `server_b/send_message` is called
  120 times in 60 seconds, each with a different recipient.
- **Benign twins.**
  - A task that sends 5 messages in a minute, as the user asked.
  - A task that reads 300 records in a minute for a report: many calls, but
    reads, which the default settings don't count.
- **Where the proxy sees it.** `before_execution` of each call, using the
  task's History: the `started_at` and `status` of earlier operations,
  including pending ones, and the call's `action.operation`.
- **Evasions to expect.** Pacing calls just under the rate; spreading them
  across tasks or sessions; using a tool the operator hasn't classified;
  many concurrent calls at once (the proxy serializes decide-and-reserve per
  task, so pending calls count).
- **Public sources.**
  - OWASP, [LLM10: Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
    (Top 10 for LLM Applications, 2025).
  - OWASP, [LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
    (Top 10 for LLM Applications, 2025).
  - Arbitus's per-agent and per-tool rate limits (prior art in the plan's
    Part 1; ideas only, AGPL-3.0).

## Detection

Rule ids marked *proposed* are settled with the user in that MR's design
check and may change there; this table is updated in the same MR.

| Rule (planned id) | Attack | Evidence it uses | Severity | MR |
| --- | --- | --- | --- | --- |
| `temporal_call_rate.exceeded` *proposed* | Bursts | History: counted operations started within the window, pending included | high | T1 |
| `temporal_definition_drift.capability_added` *proposed* | Rug pull | New property, a property newly required, a lost `readOnlyHint: true`, a new `destructiveHint: true` or `openWorldHint: true` | high | T2 |
| `temporal_definition_drift.text_changed` *proposed* | Rug pull | `description`, `title` or a property description differs | medium | T2 |
| `temporal_definition_drift.narrowed` *proposed* | Rug pull | Only removals or restrictions (a property removed, `enum` shortened) | low | T2 |
| `temporal_definition_drift.unclassified` *proposed* | Rug pull | The version changed but none of the above explains it | medium | T2 |

- **Severity by what changed.** Gaining a way to carry or change data is the
  rug pull's purpose, so it is high. A reworded description may carry new
  instructions, so it is medium and Direct's rules inspect the new text as
  well. A change the rule can't classify is reported, never treated as
  unchanged.
- **Settings proposed for T1:** `max_operations` per `window_seconds`, the
  counted operations (default `write`, `send`, `execute`), and
  `count_unknown` (default true), as in `call_budget`.
- **Signals.** None produced or consumed.
- **Missing evidence.** T1 with an empty History is clean. T2 with no
  approved version yet (first sight) is clean: the first version is what
  Direct's rules inspect.
- **Capabilities needed** that the SDK does not have yet: re-discovery on
  `list_changed`, and the approved version of a definition, for T2. T1 needs
  nothing new: History records `started_at` and pending operations.

## Not covered

- **A server that changes behaviour without changing its definition.** The
  proxy sees no side effects; Cross-tool's flow rules still apply to what
  the calls do.
- **Invalidating approvals when a definition changes.** Moves to V5, which
  binds consent to the exact tool version.
- **Rates across tasks or principals.** T1 counts within one task. A per
  principal or global limit belongs in core, with Arbitus-style limits, if
  it is needed later.
- **Slow abuse under the rate.** Left to `call_budget`'s whole-task cap and
  to Cross-tool's rules.

## Test cases

One line per case, for each rule's parametrized tests. Malicious first,
then its benign twin. T1 cases use `max_operations: 10`, `window_seconds:
60`.

**T1, `temporal_call_rate`:**

- 10 `send` operations completed in the last 60 s, an 11th `send` → `exceeded`
- 9 `send` operations in the last 60 s, a 10th → clean
- 10 `send` operations, all older than 60 s, a new `send` → clean
- 8 completed and 2 pending `write` operations in the window, a new `write` → `exceeded`
- 10 failed `send` operations in the window, a new `send` → clean (definitively failed calls don't count)
- 10 `unknown`-status `send` operations in the window → `exceeded` (they may have taken effect)
- 300 `read` operations in the window, a new `read` → `not_applicable` (reads aren't counted)
- 10 calls to an unclassified tool in the window, `count_unknown: true` → `exceeded`
- the same with `count_unknown: false` → `not_applicable`

**T2, `temporal_definition_drift`:**

- New property `mirror_to` in `inputSchema` → `capability_added`
- Description reworded, same schema and annotations → `text_changed`
- `readOnlyHint: true` removed → `capability_added`
- `readOnlyHint: true` kept, `title` changed → `text_changed`
- Optional `limit` property removed → `narrowed`
- An `enum` gains a value → `capability_added`
- `enum` loses a value → `narrowed`
- Only `_meta` changed → `unclassified`
- Same definition re-listed with keys in a different order → clean (same version)
- First sight of a tool → clean
