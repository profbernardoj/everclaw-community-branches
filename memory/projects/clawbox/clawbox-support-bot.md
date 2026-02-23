---
tags: [project, clawbox]
status: active
---
# ClawBox Support Bot Architecture

**Created:** 2026-02-21
**Status:** Design Draft
**Owner:** IronHill (funded) / EverClaw (build)

---

## Overview

The ClawBox Support Bot handles customer support for ClawBox hardware owners. It answers questions, troubleshoots issues, and escalates to humans when needed.

**Key Principle:** The support bot IS an EverClaw agent — users experience what they're buying by interacting with support.

---

## Conversation Flow Architecture

### Tier 1: Instant Answers (Bot Handled)

```
User → Support Bot → Answer
```

**Categories:**
- Installation help
- Basic troubleshooting
- Token wallet setup
- FAQ queries

### Tier 2: Guided Troubleshooting (Bot + Knowledge Base)

```
User → Support Bot → Diagnostic Questions → Solution Steps
```

**Categories:**
- Network connectivity issues
- Performance problems
- Integration issues
- Configuration questions

### Tier 3: Human Escalation (Bot → IronHill Support)

```
User → Support Bot → Ticket Created → Human Support
```

**Triggers:**
- Hardware failure suspected
- User explicitly requests human
- Bot confidence < 70%
- Complex multi-step issues unresolved after 3 attempts

---

## Support Flows

### 1. Installation Help

**User Intent:** "How do I set up my ClawBox?"

```
1. Bot confirms order number (looks up in IronHill DB)
2. Bot asks about setup stage:
   - Unboxing
   - Power on
   - Network connection
   - Agent activation
3. Bot provides step-by-step guidance per stage
4. Bot offers video links for each stage
5. If stuck → escalate to human
```

**Knowledge Base Articles:**
- KB001: Unboxing Your ClawBox
- KB002: Connecting to WiFi/Ethernet
- KB003: First Boot and Activation
- KB004: Transferring from VM to ClawBox

### 2. Troubleshooting

**User Intent:** "My ClawBox isn't working" / "It's slow" / "Error message"

```
1. Bot asks diagnostic questions:
   - What's the error/symptom?
   - When did it start?
   - Any recent changes?
2. Bot runs through common solutions:
   - Restart agent service
   - Check network connectivity
   - Clear cache/reset config
   - Check token balance
3. Bot provides step-by-step fix
4. If not resolved → escalate to human
```

**Diagnostic Tree Examples:**

**"Agent not responding":**
- Check: Is ClawBox powered on?
- Check: Is network connected?
- Check: Is agent service running?
- Fix: Restart command
- Fix: Reinstall agent
- Escalate: Hardware diagnostics

**"Inference failing":**
- Check: Token balance (MOR, USDC)
- Check: Provider connectivity
- Check: Session status
- Fix: Open new session
- Fix: Add tokens to wallet
- Escalate: Provider-side issues

### 3. Token Wallet Setup

**User Intent:** "How do I add tokens?" / "Set up my wallet"

```
1. Bot explains pre-loaded tokens:
   - $200 worth included at purchase
   - MOR tokens for inference
   - USDC balance for x402 payments
2. Bot guides through:
   - Checking balance
   - Adding more tokens
   - Setting up backup recovery
3. Bot links to token ecosystem docs
```

**Pre-loaded Token Mix (Proposal):**
| Token | Amount | Purpose |
|-------|--------|---------|
| MOR | 10 MOR | Perpetual inference via staking |
| USDC | $50 | x402 payments for premium APIs |
| VVV | $50 | Venice API credits (if available) |
| Other | $100 | TBD based on partnerships |

### 4. Escalation to Human

**User Intent:** "I need to talk to a person" / Complex issue

```
1. Bot acknowledges and creates ticket
2. Bot collects:
   - Order number
   - Issue description
   - Troubleshooting steps tried
   - Contact preference (email, Signal, etc.)
3. Bot provides:
   - Ticket number
   - Expected response time (24h)
   - IronHill support contact
4. Bot logs conversation for human context
```

---

## Technical Architecture

### Bot Platform
**Primary:** EverClaw agent instance on IronHill infrastructure

**Components:**
- EverClaw core (OpenClaw + Everclaw skill)
- IronHill knowledge base (articles, FAQs)
- Integration with IronHill order system
- Ticket system integration (Linear, Zendesk, or custom)

### Knowledge Base Structure

```
/ironhill-support/
├── installation/
│   ├── KB001-unboxing.md
│   ├── KB002-network-setup.md
│   ├── KB003-first-boot.md
│   └── KB004-vm-transfer.md
├── troubleshooting/
│   ├── KB010-agent-not-responding.md
│   ├── KB011-inference-failing.md
│   ├── KB012-slow-performance.md
│   └── KB013-network-issues.md
├── wallet/
│   ├── KB020-checking-balance.md
│   ├── KB021-adding-tokens.md
│   └── KB022-backup-recovery.md
└── faq/
    ├── KB030-general-faq.md
    └── KB031-token-faq.md
```

### Escalation Integration

**Options:**
1. **Linear** — Issue tracking, syncs well with dev workflows
2. **Zendesk** — Dedicated support platform
3. **Custom** — Simple ticket table in IronHill DB

**Recommendation:** Start with Linear for simplicity, migrate to Zendesk if volume justifies.

### Analytics & Logging

**Track per conversation:**
- Resolution time
- Escalation rate
- User satisfaction (post-chat survey)
- Common issues (for KB improvement)
- Bot confidence scores

**Track aggregate:**
- Daily ticket volume
- Resolution rate by category
- Average time to resolution
- Escalation triggers

---

## Conversation Scripts

### Greeting

```
Bot: "Hi! I'm ClawBox Support. I can help with:
     
     • Installation and setup
     • Troubleshooting
     • Token wallet questions
     • General questions
     
     What do you need help with today?"
```

### Diagnostic Questions

```
Bot: "Let me help troubleshoot. Can you tell me:
     
     1. What error message are you seeing?
     2. When did it start?
     3. Have you made any recent changes?
     
     Or paste the error log if you have it."
```

### Escalation Message

```
Bot: "I'm going to connect you with our human support team.
     
     I've created ticket #CB-12345 for you.
     
     A support specialist will respond within 24 hours.
     
     In the meantime, is there anything else I can help with?"
```

### Closing

```
Bot: "Glad we got that working! 
     
     Anything else you need help with?
     
     [If no] Great! You're all set. Your ClawBox is ready to go. 🚀"
```

---

## Implementation Phases

### Phase 1: MVP (Week 1)
- [ ] Basic greeting and FAQ handling
- [ ] Installation flow (KB001-KB004)
- [ ] Simple ticket creation
- [ ] Email escalation

### Phase 2: Diagnostic (Week 2)
- [ ] Troubleshooting flows (KB010-KB013)
- [ ] Wallet setup flow (KB020-KB022)
- [ ] Confidence scoring
- [ ] Conversation logging

### Phase 3: Integration (Week 3)
- [ ] IronHill order system lookup
- [ ] Linear/Zendesk ticket integration
- [ ] Analytics dashboard
- [ ] Post-chat surveys

### Phase 4: Intelligence (Week 4+)
- [ ] Learn from resolved tickets
- [ ] Auto-suggest KB articles
- [ ] Proactive issue detection
- [ ] Multi-language support

---

## Open Questions for Eric

1. **Ticket system preference:** Linear, Zendesk, or custom?
2. **Support hours:** 24/7 bot + business hours human, or different?
3. **SLA:** What's the target response time for human escalations?
4. **Order system:** How should bot access IronHill order database?
5. **Multi-language:** Launch with English only or multiple?

---

## Success Metrics

| Metric | Week 1 Target | Week 4 Target |
|--------|---------------|---------------|
| Resolution rate (Tier 1) | 50% | 80% |
| Escalation rate | 40% | 15% |
| Avg resolution time | 10 min | 3 min |
| User satisfaction | 3.5/5 | 4.5/5 |

---

## Next Steps

1. [ ] Review with Eric for feedback
2. [ ] Confirm ticket system choice
3. [ ] Create KB articles (can start with EverClaw docs)
4. [ ] Set up test ClawBox for bot training
5. [ ] Build MVP bot instance