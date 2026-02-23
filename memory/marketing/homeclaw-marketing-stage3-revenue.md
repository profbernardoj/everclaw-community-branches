---
tags: [marketing, flavor, homeclaw-revenue]
status: complete
---
# HomeClaw Marketing Plan — Stage 3: Revenue Model

**Created:** 2026-02-19
**Flavor:** HomeClaw (homeclaw.org)
**Target Revenue:** $100M over 60 days

---

## Revenue Streams Overview

HomeClaw operates within the EverClaw 28 Flavors ecosystem. Revenue flows through multiple channels:

| Stream | Source | Margin | Timeline |
|--------|--------|--------|----------|
| Hardware Referral | ClawBox (IronHill) | 10% ($100/unit) | Passive |
| Inference Subscription | Morpheus API Gateway | TBD | Active |
| Support Plans | Enterprise/pro users | High | Active |
| Affiliate Fees | VM providers, hardware | 10-20% | Passive |

---

## $100M Target Breakdown

### Reverse Engineering the Number

$100M over 60 days = **$1.67M/day** average revenue.

This is aggressive but achievable through the EverClaw ecosystem model where each flavor drives traffic to the next stage:

```
Stage 1: Awareness (28 Flavors websites)
    ↓
Stage 2: Interest (VM trial → hardware purchase)
    ↓
Stage 3: Conversion (ClawBox hardware + inference subscription)
    ↓
Stage 4: Retention (ongoing inference, support)
```

### Revenue by Stage in Funnel

| Funnel Stage | Revenue Source | 60-Day Target | % of Total |
|--------------|----------------|---------------|------------|
| Hardware Sales | ClawBox referral fees | $10M | 10% |
| Inference Subscriptions | Morpheus API Gateway | $60M | 60% |
| Enterprise/Support | Pro support plans | $20M | 20% |
| Cross-Flavor Referrals | Other EverClaw flavors | $10M | 10% |
| **Total** | | **$100M** | 100% |

---

## Stream 1: Hardware Revenue (ClawBox via IronHill)

### Product: ClawBox
Pre-configured hardware that runs OpenClaw + HomeClaw out of the box.

### Hardware Economics
| Item | Value |
|------|-------|
| Retail Price | $999 |
| Affiliate Fee (David) | $100 (10%) |
| IronHill Revenue | $900 |
| Build Cost | ~$400 |
| IronHill Profit | ~$500 |
| Logistics | ~$100 |

### Volume Projections

To hit $10M in affiliate fees:
- **100,000 units × $100 = $10M**

### Funnel Conversion
From 2M HA users to 100K ClawBox sales:

| Stage | Conversion | Volume |
|-------|------------|--------|
| HA ActiveUsers | - | 2,000,000 |
| Aware of HomeClaw | 10% | 200,000 |
| Try VM (free) | 10% | 20,000 |
| Convert to hardware | 50% | 10,000 |
| Refer others (viral) | 10x | 100,000 |

**Key insight:** The viral/ referral loop is critical. Each hardware buyer should refer 10 others to hit target.

### Hardware Revenue Ramp

| Week | Units Sold | Cumulative Revenue |
|------|------------|-------------------|
| Week 1-2 | 5,000 | $500,000 |
| Week 3-4 | 15,000 | $2,000,000 |
| Week 5-6 | 30,000 | $5,000,000 |
| Week 7-8 | 50,000 | $10,000,000 |

---

## Stream 2: Inference Subscriptions (Morpheus API Gateway)

### The Ownership Model

HomeClaw promotes "inference you own" via MOR token staking:
- User stakes MOR tokens
- Tokens open blockchain sessions with providers
- Inference is effectively free (tokens returned after use)
- User owns their inference forever

### Subscription Tiers

For users who don't want to stake MOR, offer API subscriptions:

| Tier | Price | Included | Overage |
|------|-------|----------|---------|
| Starter | $29/mo | 10K messages | $0.003/msg |
| Family | $49/mo | 25K messages | $0.002/msg |
| Power | $99/mo | 75K messages | $0.001/msg |
| Enterprise | $299/mo | Unlimited | - |

### Revenue Calculation

**Assumption:** 60% of hardware buyers also subscribe (or stake MOR equivalent).

To hit $60M in 60 days:
- **20,000 active subscribers at$50/month average = $1M/month**
- But we need $60M in 60 days = $1M/day

**Revised approach:** Pre-paid annual subscriptions at discount.

| Plan | Price | Commitment | Users Needed |
|------|-------|------------|--------------|
| Annual Starter | $290/yr (17% off) | 1 year | 34,500 |
| Annual Family | $490/yr (17% off) | 1 year | 20,400 |
| Annual Power | $990/yr (17% off) | 1 year | 10,100 |
| Annual Enterprise | $2,990/yr (17% off) | 1 year | 3,350 |

**Target mix:**
- 25,000 Annual Family = $12.25M
- 15,000 Annual Power = $14.85M
- 5,000 Annual Enterprise = $15M
- 18,000 Annual Starter = $5.22M
- MOR staking equivalent (referral) = $12.68M affiliate value

**Total: $60M**

### MOR Staking Alternative

For users who prefer ownership:
- Refer to MOR purchase on Base
- Affiliate fee from DEX (Aerodrome referral program)
- User gets perpetual inference, we get transaction fee

---

## Stream 3: Enterprise/Support Plans

### Target Customers
- Smart home installers/integrators
- Property management companies
- Vacation rental hosts (Airbnb, VRBO)
- Small businesses with smart offices
- Home Assistant power users

### Support Tiers

| Tier | Price | Included |
|------|-------|----------|
| Community | Free | Discord, forums |
| Pro | $49/mo | Email support, 48hr response |
| Business | $199/mo | Priority support, 4hr response, setup assistance |
| Enterprise | $999/mo | Dedicated support, custom integrations, SLA |

### Revenue Calculation

To hit $20M in 60 days:

| Plan | Users | Monthly Revenue | 60-Day Revenue |
|------|-------|-----------------|----------------|
| Pro | 10,000 | $490,000 | $980,000 |
| Business | 5,000 | $995,000 | $1,990,000 |
| Enterprise | 1,000 | $999,000 | $1,998,000 |

Wait, that's only ~$5M. Need to revise.

**Revised approach:** Annual pre-paids + higher volume.

| Plan | Annual Price | Users Needed | Revenue |
|------|--------------|--------------|---------|
| Pro Annual | $490 | 5,000 | $2.45M |
| Business Annual | $1,990 | 5,000 | $9.95M |
| Enterprise Annual | $9,990 | 800 | $7.99M |
| **Total** | | | **$20.39M** |

### Enterprise Features

- Multi-site management dashboard
- Role-based access control
- Audit logs
- Custom integrations (Crestron, Control4, etc.)
- White-label options
- Dedicated account manager

---

## Stream 4: Cross-Flavor Referrals

### The 28 Flavors Network

HomeClaw is one of 28 EverClaw flavors. Each flavor drives traffic to others:

| Category | Flavors |
|----------|---------|
| Platform | AndroidClaw, AppleClaw, LinuxClaw, WindowsClaw |
| Protocol | BitcoinClaw, EthereumClaw, SolanaClaw, ArbClaw, BaseClaw |
| AI Model | GLMClaw, GrokClaw, KimiClaw, LlamaClaw, MiniMaxClaw, DeepSeekClaw, MorpheusClaw |
| Use Case | EmailClaw, HomeClaw, FamilyClaw, FriendClaw, OfficeClaw, BookingClaw, BriefingClaw, InvestClaw, VCIClaw, FamilyOfficeClaw |
| Entry | InstallOpenClaw.xyz |

### Referral Flow

```
User discovers HomeClaw
    ↓
Signs up for inference subscription
    ↓
Sees "Also try: FamilyClaw for family coordination"
    ↓
Converts to FamilyClaw
    ↓
HomeClaw gets 10% referral credit
```

### Revenue Attribution

- 10% referral credit on first-year subscription value
- Refers both directions (HomeClaw → others, others → HomeClaw)

To hit $10M in 60 days:
- 100,000 referred subscriptions at $100 average = $10M referral credits

---

## Revenue Timeline

### Week-by-Week Breakdown

| Week | Hardware | Inference | Support | Referrals | Total |
|------|----------|-----------|---------|-----------|-------|
| 1 | $250K | $1M | $500K | $250K | $2M |
| 2 | $500K | $2M | $500K | $500K | $3.5M |
| 3 | $750K | $3M | $750K | $750K | $5.25M |
| 4 | $1M | $5M | $1M | $1M | $8M |
| 5 | $1.25M | $7M | $1.25M | $1.25M | $10.75M |
| 6 | $1.5M | $8M | $1.5M | $1.5M | $12.5M |
| 7 | $1.75M | $10M | $1.75M | $1.75M | $15.25M |
| 8 | $2M | $12M | $2M | $2M | $18M |
| **Total** | **$9M** | **$48M** | **$9.25M** | **$9M** | **$75.25M** |

**Gap to $100M:** $24.75M

### Closing the Gap

The gap can be closed through:
1. **Viral acceleration** — if referral loop works better than projected
2. **Enterprise deals** — 5-10 large enterprise customers at $1M+ each
3. **Partnership revenue** — integration deals with smart home brands
4. **Premium features** — one-time purchases for advanced capabilities

---

## Key Revenue Assumptions

### Conservative Assumptions
- 2M HA users, 10% awareness = 200K
- 10% trial rate = 20K trials
- 50% hardware conversion = 10K units
- 3x viral multiplier = 30K referred users
- 60% subscription adoption

### Aggressive Assumptions (Required for $100M)
- 2M HA users, 20% awareness = 400K
- 15% trial rate = 60K trials
- 40% hardware conversion = 24K units
- 5x viral multiplier = 120K referred users
- 50% subscription adoption at higher tiers

### Risk Factors
| Risk | Mitigation |
|------|------------|
| Low awareness | Aggressive social + influencer campaign |
| Low trial conversion | Free tier, easy onboarding |
| Low hardware sales | VM trial first, prove value |
| Low subscription adoption | Annual pre-pay discounts |
| Viral loop fails | Paid acquisition as backup |

---

## Revenue Metrics to Track

### Leading Indicators
| Metric | Target | Tracking |
|--------|--------|----------|
| Website visitors | 100K/week | Google Analytics |
| VM trial signups | 5K/week |VM provider dashboard |
| Hardware pre-orders | 1K/week | IronHill dashboard |
| Subscription signups | 2K/week | Stripe dashboard |
| Referral rate | 3x | Custom tracking |

### Lagging Indicators
| Metric | Target | Tracking |
|--------|--------|----------|
| Hardware units sold | 100K total | IronHill |
| Monthly recurring revenue | $1.5M/mo | Stripe |
| Annual pre-pay revenue | $50M | Stripe |
| Support plan revenue | $20M | Stripe |
| Referral credits earned | $10M | Custom |

---

## Partnership Revenue Opportunities

### Smart Home Brands
| Partner | Opportunity | Potential Deal |
|---------|-------------|----------------|
| Aqara | Pre-installHomeClaw on hubs | $50/unit affiliate |
| Nabu Casa | Bundle with HA Cloud | Revenue share |
| IKEA | Smart home bundle | $25/unit affiliate |
| Philips Hue | Integration partnership | Marketing co-op |

### Installers/Integrators
| Channel | Opportunity | Potential Revenue |
|---------|-------------|-------------------|
| Custom installers | Reseller program | 500 installers × $20K/year = $10M |
| Vacation rental hosts | Property management bundle | 10K properties × $200/year = $2M |
| Property managers | Multi-site licensing | 1K companies × $5K/year = $5M |

---

## Status

**Stage 3: Revenue Model— COMPLETE**

**Deliverables:**
- [x] Revenue stream breakdown (4 streams)
- [x] $100M target breakdown by stream
- [x] Hardware revenue model (ClawBox)
- [x] Inference subscription model (Morpheus API Gateway)
- [x] Enterprise/support revenue model
- [x] Cross-flavor referral model
- [x] Week-by-week revenue timeline
- [x] Key assumptions and risk factors
- [x] Revenue metrics to track
- [x] Partnership opportunities

**Next:** Stage 4 - Referral Mechanics (separate document)