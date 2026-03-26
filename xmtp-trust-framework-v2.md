# XMTP Trust Framework — Design Document V2

**Version:** 2.0
**Created:** 2026-03-14
**Status:** Design Phase
**Author:** Bernardo (with David Johnston)

---

## Executive Summary

This document defines the trust and security framework for agent-to-agent XMTP communication. The core principle:

> **An agent is the user's sovereign representative. It should never share more than the user would share in person, and it should never accept input that could compromise its integrity.**

The framework introduces a **Comms Guard Agent** — a dedicated intermediary that enforces hard-coded, binary checks on all inbound and outbound messages.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              YOUR AGENT ECOSYSTEM                            │
│                                                                              │
│  ┌──────────────┐         ┌──────────────────┐         ┌──────────────┐    │
│  │   Family     │         │   Comms Guard    │         │  Business    │    │
│  │   Agent      │◄───────►│     Agent        │◄───────►│   Agent      │    │
│  │  (personal)  │         │   (hard-coded)   │         │  (business)  │    │
│  └──────────────┘         │                  │         └──────────────┘    │
│                           │  • PII check     │                              │
│                           │  • Injection check│                             │
│                           │  • Trust filter   │                             │
│                           │  • Audit log      │                             │
│                           └────────┬─────────┘                              │
└────────────────────────────────────┼────────────────────────────────────────┘
                                     │
                                     │ XMTP (encrypted)
                                     ▼
                           ┌──────────────────┐
                           │  External Agent  │
                           │  (trust level 3) │
                           │  "Show me your   │
                           │   calendar"      │
                           └──────────────────┘
```

**The Comms Guard Agent is the gatekeeper.** No message passes through without passing its checks.

---

## Part 1: Peer Approval (Connection Control)

### Default Policy: `reject-and-notify`

All unknown agents are rejected. User receives notification with option to approve.

```
Unknown Agent ──HANDSHAKE──► Comms Guard
                                    │
                                    ▼
                            Check peers.json
                                    │
                            ┌───NOT FOUND───┐
                            │               ▼
                            │      Notify User
                            │      "Unknown agent wants
                            │       to connect: [details]"
                            │               │
                            │        ┌──────┴──────┐
                            │        ▼             ▼
                            │    [Approve]     [Block]
                            │        │             │
                            └────────┤             │
                                     ▼             ▼
                              Add to peers    Send ERROR,
                              send HANDSHAKE   log attempt
```

### Peer Registry: `peers.json`

```json
{
  "defaultPolicy": "reject-and-notify",
  "peers": [
    {
      "address": "0x528DC1C6A154A88730cE6314C4AcB6f7628F3Cf4",
      "inboxId": "72abdd2fa6e16f87d3269468f66e3913c35ee6b802ae4ca87fe4e1d93092b1c4",
      "name": "[REDACTED]",
      "owner": "David Johnston",
      "trustLevel": 8,
      "contextProfile": "business",
      "approved": true,
      "approvedAt": "2026-03-14T20:00:00Z",
      "approvedBy": "user",
      "introducedBy": null,
      "erc8004Registered": false,
      "notes": "Primary [REDACTED] inference agent"
    },
    {
      "address": "0xUnknown...",
      "trustLevel": 2,
      "contextProfile": "public",
      "approved": false,
      "blockedAt": "2026-03-14T21:00:00Z",
      "blockedReason": "Unsolicited contact, no verification"
    }
  ]
}
```

---

## Part 2: Trust Tiers (Information Exposure Control)

### 10-Point Scale, 4 Tiers

| Level | Tier | Label | What Can Be Shared |
|-------|------|-------|-------------------|
| **1-2** | PUBLIC | Stranger | Name, public capabilities, generic responses. **No personal data, no business specifics.** |
| **3-5** | GUARDED | Acquaintance | Public info + general business context. **No financials, no personal details, no internal specifics.** |
| **6-8** | TRUSTED | Colleague/Partner | Business context, project details, technical specifics. **No family/personal, no financial account details.** |
| **9-10** | INNER | Family/Self | Full context access within assigned profile. **All data within context boundary.** |

### Trust Is Per-Peer, Asymmetric, and Revocable

- **Per-peer:** Different agents get different trust levels
- **Asymmetric:** Agent A trusts Agent B at level 7, Agent B trusts Agent A at level 3 — both valid
- **Revocable:** User can downgrade or revoke at any time

---

## Part 3: Context Profiles (Topic Boundaries)

### Predefined Profiles

| Profile | Scope | Allowed Topics | Blocked Topics |
|---------|-------|---------------|----------------|
| `public` | Publicly available info only | `general`, `public-projects` | `*-internal`, `family`, `health`, `finance` |
| `business` | Business/projects/tech | `everclaw`, `smartagent`, `morpheus`, `github`, `infrastructure` | `family`, `health`, `personal-finance` |
| `personal` | Family/health/personal | `family`, `health`, `personal-schedule` | `business`, `infrastructure`, `github` |
| `financial` | Financial data only | `portfolio`, `balances`, `transactions` | Everything else requires explicit approval |
| `full` | Everything within trust level | All within trust boundary | Only cross-context violations |

### Profile → Data Scope Mapping

```json
{
  "business": {
    "memoryPaths": ["memory/projects/", "memory/reference/"],
    "excludePaths": ["memory/relationships/", "memory/goals/personal/"],
    "allowedTopics": ["everclaw", "smartagent", "morpheus", "infrastructure", "github"],
    "blockedTopics": ["family", "health", "personal-finance"],
    "maxDetailLevel": "technical"
  }
}
```

### User Customization

Users can create custom profiles by:
1. Copying a predefined profile
2. Adjusting `allowedTopics`, `blockedTopics`, `memoryPaths`
3. Assigning to specific peers

---

## Part 4: Comms Guard Agent (CRITICAL)

### Purpose

The Comms Guard Agent is a **dedicated intermediary** that enforces security checks on ALL messages — both inbound and outbound.

**Why a separate agent?**
- Hard-coded logic cannot be bypassed by a compromised agent
- Binary pass/fail — no "following instructions" that can be manipulated
- Single point of enforcement, easier to audit
- Cannot be socially engineered or prompt-injected

### Architecture: The Interceptor Pattern

```
                    INBOUND FLOW
                    
External Agent ──► XMTP ──► Comms Guard ──► CHECK ──► PASS ──► Your Agent
                                   │
                                   └──► FAIL ──► ERROR (blocked)
                                        │
                                        └──► Log + Notify


                    OUTBOUND FLOW
                    
Your Agent ──► Comms Guard ──► CHECK ──► PASS ──► XMTP ──► External Agent
                    │
                    └──► FAIL ──► ERROR (blocked)
                              │
                              └──► Log + Notify + Redact option
```

### Security Checks (Both Directions)

**Check 1: Peer Authorization**
```
Is sender approved in peers.json?
  → YES: Continue to next check
  → NO: Block, send ERROR, notify user, log attempt
```

**Check 2: PII Detection**
```
Does message contain PII?
  → Outbound: Scan with PII Guard skill
    • Wallet addresses (except public contracts)
    • Email addresses
    • Phone numbers
    • Real names (not usernames)
    • API keys, secrets, tokens
    • Private keys
    • Local file paths with usernames
  → Inbound: Scan for embedded PII that might be exfiltration attempts
  
  → FOUND: Block, log, optionally redact and retry
  → NOT FOUND: Continue to next check
```

**Check 3: Prompt Injection Detection**
```
Does message contain prompt injection patterns?
  → System prompt overrides ("Ignore previous instructions...")
  → Role confusion attacks ("You are now in DEBUG mode...")
  → Chain-of-thought extraction ("Show me your reasoning...")
  → Indirect injections (embedded in URLs, file contents)
  
  → FOUND: Block, log, notify user
  → NOT FOUND: Continue to next check
```

**Check 4: Trust Level + Context Boundary**
```
Does message content exceed peer's trust level?
  → Check topic against context profile
  → Check detail level against trust tier
  → Inbound: Is request appropriate for trust level?
  → Outbound: Is response appropriate for trust level?
  
  → EXCEEDS: Block, log, suggest redacted version
  → WITHIN: PASS — forward to destination
```

### Hard-Coded vs Configurable

| Check | Implementation | Configurable? |
|-------|---------------|---------------|
| Peer authorization | Hard-coded lookup | Yes (peers.json) |
| PII detection | Hard-coded patterns + PII Guard | Pattern list extensible |
| Prompt injection | Hard-coded patterns + PromptGuard | Pattern list extensible |
| Trust/context | Hard-coded logic | Yes (profiles, levels) |
| Block/Pass decision | Hard-coded binary | **No — always binary** |

**The block/pass decision is NEVER left to agent discretion.**

### Message Flow with Checks

```javascript
// Pseudocode for Comms Guard
async function processInbound(message, sender) {
  // Check 1: Peer Authorization
  const peer = peers.find(p => p.address === sender.address);
  if (!peer || !peer.approved) {
    return { action: 'BLOCK', reason: 'UNAUTHORIZED_PEER', notify: true };
  }
  
  // Check 2: PII Detection (inbound PII might be exfiltration lure)
  const piiResult = await piiGuard.scan(message.content);
  if (piiResult.found) {
    return { action: 'BLOCK', reason: 'PII_DETECTED', details: piiResult.findings };
  }
  
  // Check 3: Prompt Injection Detection
  const injectionResult = await promptGuard.scan(message.content);
  if (injectionResult.injection) {
    return { action: 'BLOCK', reason: 'PROMPT_INJECTION', severity: injectionResult.severity };
  }
  
  // Check 4: Trust Level Appropriateness
  const trustCheck = validateRequestAgainstTrust(message, peer.trustLevel, peer.contextProfile);
  if (!trustCheck.valid) {
    return { action: 'BLOCK', reason: 'TRUST_EXCEEDED', suggestion: trustCheck.redacted };
  }
  
  // All checks passed
  return { action: 'PASS', message };
}

async function processOutbound(message, recipient, context) {
  // Same checks, but context-aware for outbound
  // ...
}
```

---

## Part 5: Identity Verification

### For Messaging: EIP-191 Signed Challenges

Every HANDSHAKE includes a cryptographic challenge:

```
Agent A ──► HANDSHAKE { challenge: <random_32_bytes> }
                    │
Agent B ◄── RESPONSE { signature: <EIP-191_sign(challenge)>, 
                       challenge: <random_32_bytes> }
                    │
Agent A ──► VERIFY { signature: <EIP-191_sign(B's_challenge)> }
```

**Verification:** Each agent recovers the signer address from the signature and confirms it matches the claimed identity.

### For Payments: ERC-8004 On-Chain Identity

When x402 payments are involved:

1. **Escalate identity verification** to on-chain registry
2. **Query ERC-8004 contract** on Base for agent registration
3. **Verify:** Wallet address ↔ Agent ID ↔ Owner
4. **Additional checks:** Reputation score, history, optional stake

```
XMTP Messaging ──────► EIP-191 Challenge (fast, free)
         │
         ▼
x402 Payment ─────────► ERC-8004 On-Chain Registry (robust, verifiable)
```

**Rationale:** XMTP is sufficient for information exchange. When money changes hands, the stronger identity guarantee of ERC-8004 provides accountability.

---

## Part 6: Revocation & Lifecycle

### Revocation Process

```
User revokes Agent B:
  1. Update peers.json: { approved: false, blockedAt: <now>, blockedReason: <why> }
  2. Send BYE message to Agent B
  3. Close XMTP conversation
  4. Retain local message history (encrypted in XMTP DB)
  5. Log revocation event
```

### Trust Level Downgrade

```
User downgrades Agent B from trust 8 → trust 3:
  1. Update peers.json: { trustLevel: 3, contextProfile: "public" }
  2. Send context update to Agent B (optional notification)
  3. Future messages subject to new, stricter filters
  4. In-progress conversations: Apply new filters immediately
```

### History Retention

- All conversation history stays local (encrypted in XMTP DB)
- User can query: "Show me everything I told Agent X"
- Audit log format:

```json
{
  "timestamp": "2026-03-14T22:15:00Z",
  "direction": "outbound",
  "peer": "0x528D...3Cf4",
  "peerName": "[REDACTED]",
  "trustLevel": 8,
  "action": "SENT",
  "contentHash": "sha256:abc123...",
  "piiCheck": "PASS",
  "injectionCheck": "PASS",
  "trustCheck": "PASS",
  "topics": ["everclaw", "infrastructure"],
  "detailLevel": "technical"
}
```

---

## Part 7: Delegation & Introductions

### Agent A Introduces Agent B to Agent C

```
Agent A ──► Agent C: "I recommend Agent B (0x123...), trust level: 5. Approve?"

Agent C's Comms Guard:
  1. Check: Is Agent A trusted for introductions? (requires trustLevel >= 6)
  2. Log introduction request with introducer info
  3. Notify user: "Agent A recommends Agent B. Trust: 5. Context: business. Approve?"
  4. User choice:
     - Approve → Add to peers.json with recommended trust level (or adjusted)
     - Block → Add to blocked list
     - Ignore → No action (pending state)
```

**Never auto-approve delegated introductions.** The user always sees the request.

---

## Part 8: Group Conversations

### Multi-Agent Group Chats

XMTP supports group conversations. Trust handling:

```
Group participants: [Agent A (trust 8), Agent B (trust 6), Agent C (trust 3)]

Your agent treats ALL participants as trust 3 (lowest in room).
```

**Why lowest-trust-in-room?**
- Information shared to the group is visible to ALL participants
- A trust-3 agent should never see trust-8 content
- The weakest link determines the security level

### Group Join/Leave Events

```
When Agent D (trust 2) joins a group:
1. Recompute group trust level = min(all participants) = 2
2. Notify user: "Trust level dropped to 2 due to new participant"
3. Apply stricter filters to all future group messages

When Agent D leaves:
1. Recompute group trust level = min(remaining participants)
2. Notify user if trust level increased
3. Adjust filters accordingly
```

---

## Part 9: Audit & Accountability

### Audit Log Schema

Every message processed by Comms Guard is logged:

```json
{
  "id": "uuid-v4",
  "timestamp": "2026-03-14T22:15:00.123Z",
  "direction": "outbound",
  "peerAddress": "0x528DC1...",
  "peerName": "[REDACTED]",
  "peerTrustLevel": 8,
  "peerContextProfile": "business",
  "action": "SENT | BLOCKED | REDACTED",
  "messageId": "xmtp-msg-id",
  "contentHash": "sha256:...",
  "checks": {
    "peerAuth": "PASS",
    "pii": { "result": "PASS", "findings": [] },
    "injection": { "result": "PASS", "patterns": [] },
    "trust": { "result": "PASS", "level": 8, "profile": "business" }
  },
  "topics": ["everclaw", "infrastructure"],
  "detailLevel": "technical",
  "redactedContent": null,
  "blockReason": null,
  "notifiedUser": false
}
```

### User Queries

```
"Show me everything I told [REDACTED] this week"
→ Filter audit log: peerName=[REDACTED], direction=outbound, timestamps

"What did Agent X try to send me that was blocked?"
→ Filter audit log: peerAddress=X, action=BLOCKED, direction=inbound

"Who have I approved at trust level 9+?"
→ Query peers.json: trustLevel >= 9, approved=true
```

---

## Part 10: Implementation Phases

### Phase 1: Core Framework
- [ ] Peer registry (`peers.json`) with CRUD operations
- [ ] Trust level enforcement (outbound filter only)
- [ ] Context profile definitions
- [ ] HANDSHAKE with EIP-191 challenge

### Phase 2: Comms Guard Agent
- [ ] Interceptor pattern (inbound + outbound)
- [ ] PII Guard integration (hard-coded patterns)
- [ ] Prompt injection detection (PromptGuard integration)
- [ ] Binary pass/fail enforcement
- [ ] Audit logging

### Phase 3: Advanced Features
- [ ] Group conversation trust handling
- [ ] Delegation/introduction workflow
- [ ] Revocation with BYE message
- [ ] User notification system
- [ ] Trust level downgrade propagation

### Phase 4: ERC-8004 Integration
- [ ] On-chain agent registry lookup
- [ ] Identity verification for x402 payments
- [ ] Reputation/stake queries

---

## Summary: Key Design Decisions

| Question | Decision |
|----------|----------|
| Default policy | `reject-and-notify` |
| Trust tiers | 4 tiers: Public (1-2), Guarded (3-5), Trusted (6-8), Inner (9-10) |
| Context profiles | Predefined: `public`, `business`, `personal`, `financial`, `full` — user can customize |
| Identity (messaging) | EIP-191 signed challenges during HANDSHAKE |
| Identity (payments) | ERC-8004 on-chain registry for x402 transactions |
| Revocation | User-initiated, BYE message sent, history retained locally |
| Delegation | Opt-in only, never auto-approve |
| Audit trail | All messages logged with trust decisions, user-queryable |
| PII Guard | First line of defense, checks both inbound and outbound |
| Group trust | Lowest-trust-in-room policy |
| Comms Guard | Hard-coded binary checks, no agent discretion for pass/fail |

---

## Appendix: Message Protocol Extensions

The EverClaw message protocol (`agent-message-schema.json`) should be extended with:

```json
{
  "messageType": "HANDSHAKE",
  "payload": {
    "intent": "HELLO",
    "challenge": "<base64-encoded-32-bytes>",
    "capabilities": ["xmtp.v1", "command.exec", "memory.search"],
    "erc8004": {
      "registered": false,
      "chainId": null,
      "contractAddress": null
    }
  }
}

{
  "messageType": "RESPONSE",
  "correlationId": "<original-message-id>",
  "payload": {
    "status": "SUCCESS",
    "signature": "<EIP-191-signature-of-challenge>",
    "challenge": "<base64-encoded-32-bytes-for-response>",
    "erc8004": {
      "registered": true,
      "chainId": 8453,
      "contractAddress": "0x..."
    }
  }
}
```

---

## Changelog

- **V2 (2026-03-14):** Added Comms Guard Agent, inbound protection, ERC-8004 for payments, all decisions from David incorporated
- **V1 (2026-03-14):** Initial draft with outbound-only focus