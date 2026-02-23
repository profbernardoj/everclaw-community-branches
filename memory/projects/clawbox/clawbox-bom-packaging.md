---
tags: [project, clawbox]
status: active
---
# ClawBox BOM & Packaging Options

**Created:** 2026-02-21
**Status:** Decision Document for Eric @ IronHill
**Product:** ClawBox — Pre-built EverClaw Hardware

---

## Overview

This document outlines options for ClawBox branding, packaging, and included features. Eric requested clarity on:
1. Branding customization (28 flavors vs single ClawBox brand)
2. Affiliate branding (include affiliate logos on sticker/box)
3. Monitor/keyboard add-on options
4. Pre-loaded tokens (which tokens, how loaded)

---

## Option 1: Branding Strategy

### A. Single ClawBox Brand (Simpler)

**Approach:** All boxes ship with "ClawBox" branding. Flavor selection happens at software setup.

**Pros:**
- Single SKU, simpler manufacturing
- One box design, one sticker
- Lower inventory complexity
- Easier quality control

**Cons:**
- Less personalized unboxing
- No flavor-specific differentiation at hardware level
- Missed opportunity for "BitcoinClaw Edition" premium pricing

**Cost Impact:** None (standard branding)

---

### B. 28 Flavor Brands (Customizable)

**Approach:** Each box has flavor-specific branding. User selects flavor at purchase, receives matching box.

**Pros:**
- Premium unboxing experience
- Targeted marketing (BitcoinClaw for Bitcoiners)
- Higher perceived value
- Potential for flavor-specific pricing

**Cons:**
- 28 SKUs to manage
- Higher inventory complexity
- Must forecast demand per flavor
- Custom stickers per flavor

**Cost Impact:**
- Stickers: +$0.50-1.00 per unit (custom print)
- Box printing: +$2-3 per unit (custom boxes)
- Inventory overhead: +$0.50 per unit (forecasting, storage)

**Total added cost per unit:** ~$3-5

---

### C. Hybrid Approach (Recommended)

**Approach:** Standard "ClawBox" box + flavor-specific sticker.

**Details:**
- All boxes share the same outer box (ClawBox branding)
- Include flavor sticker inside box
- User applies sticker to customize their ClawBox
- Software setup guides them to their flavor's EverClaw instance

**Pros:**
- Single SKU for box
- Still feels personalized
- Lower cost than full customization
- User participates in customization

**Cons:**
- Slightly less premium than full custom box
- User must apply sticker (minor friction)

**Cost Impact:**
- Standard box: $0 extra
- Flavor sticker pack: +$0.50 per unit
- **Total added cost per unit:** ~$0.50

**Recommendation:** Hybrid Approach (Option C)

---

## Option 2: Affiliate Branding

### Approach: Affiliate Sticker

**Proposal:** Include a small sticker (2"x2") on the box that says:
> "Referral from [Affiliate Logo]"

**Use Cases:**
- Bitcoin influencer refers → their logo on box
- YouTube creator → their channel branding
- Community site → their logo

**Implementation:**
- IronHill prints affiliate stickers based on referral source
- Applied at packaging time
- Tracking matches order source to sticker

**Cost Impact:**
- Custom sticker: +$0.25 per unit
- Printing overhead: Minimal (already printing flavor stickers)

**Tracking:**
- Order comes in with affiliate code
- Warehouse receives instruction: "Apply [Affiliate] sticker to this order"
- Affiliate gets credit for referral

**Recommendation:** Offer affiliate stickers for orders >10 units

---

## Option 3: Monitor & Keyboard Add-On

### Option A: No Add-On (Standard)
- ClawBox only
- User supplies own monitor, keyboard, mouse
- Headless/SSH access also supported

**Cost:** $0 extra

### Option B: Monitor Add-On
- Bundle with 24" monitor
- IronHill sources bulk monitors
- Ships in separate box or combo box

**Monitor Options:**
| Size | Cost (Bulk) | Retail Value | Margin |
|------|-------------|--------------|--------|
| 21.5" | $80 | $120 | $40 |
| 24" | $110 | $170 | $60 |
| 27" | $150 | $220 | $70 |

**Recommendation:** Offer 24" monitor as standard add-on

### Option C: Keyboard/Mouse Combo
- Bundle with wireless keyboard + mouse
- Basic productivity setup

**Keyboard/Mouse Options:**
| Type | Cost (Bulk) | Retail Value | Margin |
|------|-------------|--------------|--------|
| Basic wireless combo | $25 | $40 | $15 |
| Mechanical keyboard + mouse | $60 | $100 | $40 |
| Premium wireless combo | $45 | $75 | $30 |

**Recommendation:** Offer basic wireless combo as add-on

### Option D: Full Setup Bundle
- ClawBox + 24" monitor + keyboard + mouse
- Everything needed to start
- Premium price point

**Bundle Pricing:**
| Bundle | Components | Bundle Price | Margin |
|--------|------------|--------------|--------|
| Starter | ClawBox only | $1,200 | $300-400 |
| Desktop | ClawBox + 24" monitor + KB/mouse | $1,450 | $380-480 |
| Premium | ClawBox + 27" monitor + mechanical KB + mouse | $1,600 | $420-520 |

**Recommendation:** Offer Starter (default) and Desktop (add-on) bundles

---

## Option 4: Pre-Loaded Tokens

### Proposal: $200 Worth of Tokens Included

**Question:** Which tokens? How loaded?

### Token Mix Options

#### A. MOR-Heavy (Recommended)
**Philosophy:** Emphasize perpetual inference ownership

| Token | Amount | Value | Purpose |
|-------|--------|-------|---------|
| MOR | 10 MOR | $150 | Perpetual inference via staking |
| USDC | $50 | $50 | x402 payments, API credits |

**Why MOR heavy:**
- Aligns with "own your inference" message
- MOR staking = inference forever
- USDC gives flexibility for other services

---

#### B. Balanced Mix
**Philosophy:** Cover multiple inference options

| Token | Amount | Value | Purpose |
|-------|--------|-------|---------|
| MOR | 5 MOR | $75 | Morpheus inference |
| USDC | $50 | $50 | x402 payments |
| VVV (Venice) | $50 | $50 | Venice API credits |
| ETH | $25 | $25 | Gas fees for transactions |

**Why balanced:**
- Multiple inference options
- User can choose their preference
- More complex to explain

---

#### C. USDC Only (Simplest)
**Philosophy:** Maximum flexibility, user chooses

| Token | Amount | Value | Purpose |
|-------|--------|-------|---------|
| USDC | $200 | $200 | Buy any token, pay any service |

**Why USDC only:**
- Simplest for user to understand
- No lock-in to any token
- User chooses their path
- Easier to source (no token-specific relationships)

---

### How Tokens Are Loaded

**Options:**

#### A. Pre-Loaded Wallet on Device
**Method:** IronHill creates wallet, loads tokens, seals device

**Pros:**
- True "out of box" experience
- User starts with tokens ready

**Cons:**
- IronHill custody until delivery
- Security risk (wallet on device in transit)
- Not user-controlled until delivery

---

#### B. Redemption Code (Recommended)
**Method:** Box includes redemption code, user claims tokens to their own wallet

**Process:**
1. User receives ClawBox
2. User sets up wallet (on device)
3. User enters redemption code
4. Tokens transferred to user wallet

**Pros:**
- User controls wallet from day 1
- No custody risk for IronHill
- User learns to use wallet during setup
- Redemption can be for any token mix

**Cons:**
- Extra step for user
- Requires redemption infrastructure

---

#### C. QR Code Scratch-Off
**Method:** Box includes scratch-off QR code with seed phrase

**Process:**
1. User scratches off to reveal QR
2. User scans or enters seed phrase
3. Wallet contains pre-loaded tokens

**Pros:**
- Physical security (scratch-off)
- User controls from reveal

**Cons:**
- Users might lose/ignore scratch-off
- Still need to load tokens to wallet

---

### Token Sourcing

**Model:** IronHill buys tokens on market or partners with token projects

**Partner Opportunities:**
| Token | Potential Partner | Deal |
|-------|-------------------|------|
| MOR | Morpheus community | Discount or grant for bulk |
| VVV | Venice | Co-marketing, credits |
| ETH | N/A | Market purchase |
| USDC | N/A | Circle, market purchase |

---

## Summary of Recommendations

| Option | Recommendation | Rationale |
|--------|----------------|-----------|
| Branding | Hybrid (standard box + flavor sticker) | Single SKU, still personalized |
| Affiliate branding | Yes, for orders >10 units | Tracks referrals, creates value |
| Monitor/keyboard | Desktop bundle add-on ($1,450) | Complete solution option |
| Token mix | MOR-heavy (10 MOR + $50 USDC) | Aligns with ownership message |
| Token loading | Redemption code | User control, no custody risk |

---

## Questions for Eric

1. **Branding:** Confirm hybrid approach (standard box + flavor sticker)?
2. **Affiliate sticker:** Minimum order quantity to include affiliate branding?
3. **Monitor/keyboard:** Which bundles to offer? Starter + Desktop, or add Premium?
4. **Token mix:** Confirm MOR-heavy (10 MOR + $50 USDC) or prefer balanced/USDC only?
5. **Token loading:** Redemption code infrastructure — who builds?
6. **Token sourcing:** Partner with Morpheus for MOR discount? Venice for VVV?

---

## Next Steps

1. [ ] Eric confirms preferences
2. [ ] IronHill sources stickers, monitors, keyboards
3. [ ] Build redemption code infrastructure (IronHill or EverClaw team?)
4. [ ] Negotiate token partnerships (Morpheus, Venice)
5. [ ] Finalize bundle pricing
6. [ ] Update pre-order site with bundle options