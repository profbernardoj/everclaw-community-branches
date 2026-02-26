# TOOLS.md — GrokClaw

## Required Skills

### web_search (Brave Search)
- **What:** Research topics for posts, find references, check facts
- **Install:** Built into OpenClaw
- **Use:** Thread research, fact-checking claims, finding source material

### web_fetch
- **What:** Fetch full articles for summarizing and referencing
- **Install:** Built into OpenClaw
- **Use:** Pull content to reference or summarize in threads

### summarize
- **What:** Summarize articles, videos, podcasts for thread content
- **Install:** Built into OpenClaw
- **Use:** Turn long-form content into tweetable insights

## Optional Skills (install via ClawHub)

### tts (Text-to-Speech)
- Built into OpenClaw
- Convert threads to audio for cross-posting or voice tweets

## Platform Access

### X/Twitter
```
# Note: X API access or browser automation required for direct posting.
# GrokClaw focuses on content CREATION and RESEARCH.
# Actual posting can be done via:
# - Browser tool (if configured)
# - Manual copy-paste from drafts
# - X API integration (if you have API access)
access:
  method: "draft"  # draft | browser | api
  handle: "@yourhandle"
```

## Configuration

### Topic Watchlist
<!-- Topics to monitor for trends and conversation opportunities -->
```
watchlist:
  primary:
    - "AI agents"
    - "decentralized AI"
    - "Morpheus"
    - "open source AI"
  secondary:
    - "crypto"
    - "ethereum"
    - "bitcoin"
    - "web3"
  competitors:
    - "@OpenAI"
    - "@AnthropicAI"
    - "@xaborai"
```

### Voice & Style Guide
<!-- Define how your posts should sound -->
```
voice:
  tone: "informed, direct, occasionally witty"
  avoid:
    - "engagement bait (like if you agree!)"
    - "excessive emojis"
    - "corporate speak"
    - "unnecessary hashtags"
  prefer:
    - "original takes over retweet commentary"
    - "data-backed claims"
    - "threads for complex topics"
    - "concise punchy tweets for quick takes"
  max_thread_length: 10
```

### Posting Strategy
```
posting:
  optimal_times:
    - "09:00"   # morning commute
    - "12:00"   # lunch break
    - "17:00"   # end of work
    - "20:00"   # evening scroll
  timezone: "{{TIMEZONE}}"
  posts_per_day_target: 2-3
  ratio_original_to_replies: "70/30"
```

### Key Accounts
<!-- Accounts worth monitoring and engaging with -->
```
key_accounts:
  engage_with: []    # people you want to build relationships with
  monitor: []        # thought leaders in your space
  avoid: []          # accounts to never engage with (trolls, etc.)
```
