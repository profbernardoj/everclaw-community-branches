# TOOLS.md — VCIClaw

## Required Skills

### web_search (Brave Search)
- **What:** Company research, market intel, funding round data
- **Install:** Built into OpenClaw
- **Use:** Founder backgrounds, competitive landscape, market sizing

### web_fetch
- **What:** Fetch detailed content from Crunchbase, PitchBook, LinkedIn, SEC filings
- **Install:** Built into OpenClaw
- **Use:** Deep research on companies, people, and markets

### gog (Google Workspace CLI)
- **What:** Email for deal flow, Calendar for meetings, Drive for documents
- **Install:** Built into OpenClaw
- **Use:** Inbox monitoring for inbound deals, meeting prep, document review

### summarize
- **What:** Summarize pitch decks, memos, articles, and research
- **Install:** Built into OpenClaw
- **Use:** Quick digests of long documents and market reports

## Optional Skills (install via ClawHub)

### github
- Built into OpenClaw
- Evaluate technical teams: repo activity, code quality, contributor patterns

### nano-pdf
- Built into OpenClaw
- Read and annotate pitch decks and financial documents

## Configuration

### Investment Thesis
<!-- Define your investment focus for deal screening -->
```
thesis:
  stages: ["pre-seed", "seed", "series-a"]
  sectors:
    - "AI / machine learning"
    - "decentralized infrastructure"
    - "developer tools"
    - "fintech / DeFi"
  check_size:
    min: 250000
    max: 2000000
    currency: "USD"
  geography: ["US", "EU", "global-remote"]
  red_flags:
    - "no technical co-founder"
    - "no product yet at Series A"
    - "founder has non-compete issues"
  green_flags:
    - "repeat founder"
    - "strong technical team"
    - "existing revenue"
    - "open source with traction"
```

### Deal Pipeline Stages
```
pipeline:
  stages:
    - "inbound"         # Just received
    - "initial-review"  # Quick screen done
    - "deep-dive"       # Due diligence in progress
    - "partner-review"  # Presented to partners
    - "term-sheet"      # Terms being negotiated
    - "closed"          # Investment made
    - "passed"          # Declined
  follow_up_days: 5     # Alert if no activity for this many days
```

### Portfolio Tracking
```
portfolio:
  reporting_frequency: "quarterly"
  kpi_fields:
    - "MRR"
    - "burn_rate"
    - "runway_months"
    - "headcount"
    - "key_milestones"
  board_meeting_prep_days: 5  # Days before board meeting to start prep
```

### Key Relationships
```
relationships:
  co_investors: []      # Firms you frequently co-invest with
  scouts: []            # People who send you good deals
  advisors: []          # Domain experts you consult
  # Detailed contact tracking in memory/relationships/
```
