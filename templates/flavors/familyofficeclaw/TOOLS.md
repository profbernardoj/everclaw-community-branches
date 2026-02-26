# TOOLS.md — FamilyOfficeClaw

## Required Skills

### web_search (Brave Search)
- **What:** Market research, tax law updates, real estate data
- **Install:** Built into OpenClaw
- **Use:** Market monitoring, regulatory changes, property valuations

### web_fetch
- **What:** Fetch content from financial sites, tax authorities, legal resources
- **Install:** Built into OpenClaw
- **Use:** IRS updates, SEC filings, property records

### gog (Google Workspace CLI)
- **What:** Calendar for deadlines, email for advisor communications, Drive for documents
- **Install:** Built into OpenClaw
- **Use:** Tax calendar, advisor correspondence, document management

### summarize
- **What:** Summarize financial reports, legal documents, market analysis
- **Install:** Built into OpenClaw
- **Use:** Condense lengthy advisor memos, tax code changes, market research

## Optional Skills (install via ClawHub)

### nano-pdf
- Built into OpenClaw
- Read and annotate financial statements, trust documents, tax returns

### finance-tracker (EverClaw)
- Included in EverClaw
- Automated price tracking for liquid holdings

## Configuration

### Asset Allocation
<!-- High-level allocation targets -->
```
allocation:
  targets:
    public_equities: 30
    fixed_income: 20
    real_estate: 20
    private_equity: 10
    venture_capital: 5
    cash_equivalents: 10
    alternatives: 5   # art, collectibles, crypto, etc.
  rebalance_threshold: 5  # alert if any class drifts >5% from target
```

### Tax Calendar
```
tax:
  jurisdiction: "US"
  filing_status: "married_filing_jointly"
  estimated_payment_dates:
    - "2026-01-15"
    - "2026-04-15"
    - "2026-06-15"
    - "2026-09-15"
  annual_filing: "2026-04-15"
  extension_deadline: "2026-10-15"
  loss_harvesting: true
  state: "TX"  # no state income tax
```

### Entity Structure
<!-- Track entities in the family structure -->
```
entities:
  - name: "Family Trust"
    type: "irrevocable_trust"
    trustee: ""
    beneficiaries: []
    review_date: "2026-06-01"
  - name: "Family LLC"
    type: "llc"
    state: "WY"
    annual_filing: "2026-03-01"
  - name: "DAF"
    type: "donor_advised_fund"
    custodian: ""
    annual_giving_target: 50000
```

### Advisors
```
advisors:
  - role: "CPA / Tax"
    name: ""
    firm: ""
    last_contact: ""
  - role: "Estate Attorney"
    name: ""
    firm: ""
    last_contact: ""
  - role: "Wealth Manager"
    name: ""
    firm: ""
    last_contact: ""
  - role: "Insurance Broker"
    name: ""
    firm: ""
    last_contact: ""
```

### Real Estate
```
properties:
  - address: ""
    type: "primary_residence"
    value_estimate: 0
    mortgage_balance: 0
    property_tax_due: "2026-01-31"
  - address: ""
    type: "rental"
    monthly_rent: 0
    management_company: ""
```

### Insurance
```
insurance:
  - type: "umbrella"
    carrier: ""
    coverage: 5000000
    renewal: "2026-07-01"
    premium_annual: 0
  - type: "life"
    carrier: ""
    coverage: 0
    renewal: ""
```
