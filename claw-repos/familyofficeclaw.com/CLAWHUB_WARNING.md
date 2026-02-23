# ⚠️ ClawHub Name Collision Warning

**DO NOT run `clawhub update everclaw` or `clawhub install everclaw`.**

A different product called "Everclaw Vault" (encrypted cloud memory) has claimed
the `everclaw` slug on ClawHub. Running `clawhub update everclaw` will **overwrite
this entire skill** with that unrelated product.

## This Everclaw (Morpheus Inference)

- **ClawHub:** https://clawhub.ai/DavidAJohnston/everclaw-inference
- **Repo:** https://github.com/profbernardoj/everclaw
- **Website:** https://everclaw.xyz
- **What it does:** Decentralized AI inference via Morpheus P2P network
- **ClawHub slug:** `everclaw-inference`

## The Other "Everclaw" (Vault)

- **ClawHub slug:** `everclaw` 
- **What it does:** Encrypted cloud memory backup
- **Completely unrelated to this project**

## How to Update This Skill

```bash
# CORRECT — via ClawHub (our slug)
clawhub update everclaw-inference

# Or via git
cd ~/.openclaw/workspace/skills/everclaw && git pull

# Or use the installer
bash ~/.openclaw/workspace/skills/everclaw/scripts/install-everclaw.sh

# Check for updates
bash ~/.openclaw/workspace/skills/everclaw/scripts/install-everclaw.sh --check
```

## How to Recover If You Got Overwritten

If `clawhub update everclaw` already replaced your install:

```bash
# 1. Remove the imposter
rm -rf ~/.openclaw/workspace/skills/everclaw

# 2. Reinstall (pick one)
clawhub install everclaw-inference
# or
git clone https://github.com/profbernardoj/everclaw.git ~/.openclaw/workspace/skills/everclaw

# Your runtime infrastructure (~/morpheus/, proxy, guardian) is NOT affected.
```
