# Threat Intelligence Dashboard

An MVP threat intelligence dashboard built with Streamlit. The project collects security-related posts from Reddit, analyzes CVEs, attack types, and severity, then visualizes the results in an interactive dashboard.

## Features

- Collects Reddit posts from security-focused subreddits: `netsec`, `cybersecurity`, `malware`, `hacking`, `blueteamsec`.
- Stores raw Reddit data in `data/reddit_raw.csv`.
- Analyzes post content to:
  - Extract CVE identifiers.
  - Classify attack types: `exploit`, `ransomware`, `malware`, `phishing`, `leak`, `ddos`, `other`.
  - Calculate `severity_score` and assign `Low`, `Medium`, `High`, or `Critical` severity labels.
- Displays a Streamlit dashboard with:
  - Summary KPIs.
  - Severity distribution chart.
  - Threat trend by day.
  - Attack type distribution.
  - Top threat sources.
  - Top CVEs.
  - Latest threat posts and High/Critical alerts.
- Includes a GitHub Actions workflow for daily data updates.

## Project Structure

```text
.
|-- app.py                         # Streamlit dashboard
|-- requirements.txt               # Python dependencies
|-- data/
|   |-- reddit_raw.csv             # Raw Reddit data
|   `-- analyzed_posts.csv         # Analyzed data used by the dashboard
|-- src/
|   |-- collector_reddit_json.py   # Reddit JSON data collector
|   `-- analyzer.py                # CVE, attack type, and severity analyzer
`-- .github/
    `-- workflows/
        `-- daily_update.yml       # Daily data update workflow
```

## Requirements

- Python 3.12 recommended.
- pip.
- Reddit/API credentials if you plan to use environment variables from `.env`.

Main dependencies:

```text
streamlit
pandas
plotly
numpy
requests
python-dotenv
```

## Installation

Create a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Environment Configuration

The `.env` file should not be committed to Git. This repository already ignores `.env`.

Example:

```env
REDDIT_CLIENT_ID=your_client_id
REDDIT_CLIENT_SECRET=your_client_secret
REDDIT_USER_AGENT=threat-intel-dashboard/1.0 by your_username
```

Note: the current collector uses Reddit's public JSON endpoint with a `User-Agent` defined in the code. To use OAuth/API credentials from `.env`, extend `src/collector_reddit_json.py`.

## Collect and Analyze Data

Run the collector:

```powershell
python src\collector_reddit_json.py
```

Run the analyzer:

```powershell
python src\analyzer.py
```

After these steps, the dashboard reads from:

```text
data/analyzed_posts.csv
```

## Run the Dashboard

```powershell
streamlit run app.py
```

By default, Streamlit serves the dashboard at:

```text
http://localhost:8501
```

## Dashboard Input Data

`app.py` expects `data/analyzed_posts.csv` to include these main columns:

```text
created_utc
source
title
selftext
score
num_comments
permalink
text_norm
cves
attack_type
severity_score
severity
```

If this file is missing or has an invalid schema, regenerate it:

```powershell
python src\collector_reddit_json.py
python src\analyzer.py
```

## GitHub Actions

The workflow at `.github/workflows/daily_update.yml` automatically:

1. Installs dependencies.
2. Runs the Reddit collector.
3. Runs the analyzer.
4. Commits and pushes changes to `data/reddit_raw.csv` and `data/analyzed_posts.csv`.

Current schedule:

```yaml
cron: "0 1 * * *"
```

This runs daily at 01:00 UTC. The workflow can also be triggered manually with `workflow_dispatch`.

## Security Notes

- Do not commit `.env`, API keys, or secrets.
- Review files in `data/` before publishing the repository because Reddit posts may contain links, sensitive content, or IOCs.
- The scoring logic in `src/analyzer.py` is rule-based. It is suitable for an MVP but should not replace manual threat intelligence validation.

