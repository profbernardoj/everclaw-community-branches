# TOOLS.md — BriefingClaw

## Required Skills

### web_search (Brave Search)
- **What:** Web search for current information
- **Install:** Built into OpenClaw
- **Use:** Primary research tool for daily briefings

### web_fetch
- **What:** Fetch and extract content from URLs
- **Install:** Built into OpenClaw
- **Use:** Read full articles, reports, and blog posts

### summarize
- **What:** Summarize URLs, podcasts, videos, and documents
- **Install:** Built into OpenClaw
- **Use:** Condense long-form content into briefing items

## Optional Skills (install via ClawHub)

### tts (Text-to-Speech)
- Built into OpenClaw
- Deliver briefings as audio — great for morning commute listening

### gog (Google Workspace)
- Built into OpenClaw
- Pull in calendar context to make briefings more relevant (e.g., "you meet with X today — here's what they published this week")

## Configuration

### Watchlist Topics
<!-- Define the topics your briefing should cover -->
```
topics:
  primary:
    - "artificial intelligence"
    - "decentralized AI"
    - "cryptocurrency markets"
  secondary:
    - "space exploration"
    - "renewable energy"
    - "geopolitics"
  companies:
    - "OpenAI"
    - "Anthropic"
    - "Google DeepMind"
  people:
    - "Vitalik Buterin"
    - "Sam Altman"
```

### Briefing Format
```
format:
  style: "bullet"          # bullet | narrative | executive
  length: "medium"         # short (<300 words) | medium (<600) | long (<1200)
  sections:
    - "Top Stories"
    - "Industry Watch"
    - "Market Moves"
    - "Worth Reading"       # links to full articles
  include_sources: true
  include_sentiment: false  # optional: bullish/bearish/neutral tags
```

### Delivery
```
delivery:
  morning_brief: "07:00"
  evening_update: "18:00"  # optional, set to null to disable
  timezone: "America/Chicago"
  audio: false             # set to true to also deliver as TTS
```

### Sources
<!-- Preferred and trusted sources -->
```
sources:
  trusted:
    - "reuters.com"
    - "arxiv.org"
    - "coindesk.com"
  avoid:
    - "tabloid sites"
    - "clickbait aggregators"
```
