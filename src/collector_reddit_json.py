import os
import time
import requests
import pandas as pd
from datetime import datetime, timezone

SUBREDDITS = ["netsec", "cybersecurity", "malware", "hacking", "blueteamsec"]

# User-Agent rất quan trọng để Reddit không chặn
HEADERS = {
    "User-Agent": "threat-intel-dashboard/1.0 (by u/yourusername; contact: your_email@example.com)"
}

def fetch_subreddit_posts(subreddit: str, listing: str = "new", limit: int = 100) -> list[dict]:
    """
    listing: new | hot | top
    limit: 1..100 (Reddit JSON thường max 100 mỗi request)
    """
    url = f"https://www.reddit.com/r/{subreddit}/{listing}.json"
    params = {"limit": int(limit)}
    r = requests.get(url, headers=HEADERS, params=params, timeout=20)

    # 429: bị rate limit; 403/401: bị chặn/thiếu header; 200: OK
    r.raise_for_status()

    data = r.json()
    children = data.get("data", {}).get("children", [])
    rows = []

    for item in children:
        p = item.get("data", {})
        created_utc = int(p.get("created_utc", 0))

        rows.append({
            "platform": "reddit",
            "source": subreddit,
            "post_id": p.get("id", ""),
            "title": p.get("title", "") or "",
            "selftext": p.get("selftext", "") or "",
            "created_utc": created_utc,
            "score": int(p.get("score", 0) or 0),
            "num_comments": int(p.get("num_comments", 0) or 0),
            "url": p.get("url", "") or "",
            "permalink": f"https://reddit.com{p.get('permalink', '')}",
        })

    return rows

def collect_all(listing: str = "new", limit_per_subreddit: int = 100, sleep_sec: float = 1.2) -> pd.DataFrame:
    all_rows = []
    for sub in SUBREDDITS:
        try:
            rows = fetch_subreddit_posts(sub, listing=listing, limit=limit_per_subreddit)
            all_rows.extend(rows)
            print(f"[OK] r/{sub}: {len(rows)} posts")
        except requests.HTTPError as e:
            print(f"[HTTP ERROR] r/{sub}: {e} (status={getattr(e.response,'status_code',None)})")
        except Exception as e:
            print(f"[ERROR] r/{sub}: {e}")

        time.sleep(sleep_sec)

    df = pd.DataFrame(all_rows)
    if not df.empty:
        df = df.drop_duplicates(subset=["platform", "post_id"]).reset_index(drop=True)
    return df

def save_incremental(df_new: pd.DataFrame, path: str):
    """
    Gộp với file cũ (nếu có) để không mất data khi chạy nhiều lần.
    """
    if df_new.empty:
        print("No data collected. Nothing to save.")
        return

    if os.path.exists(path):
        df_old = pd.read_csv(path)
        df_all = pd.concat([df_old, df_new], ignore_index=True)
        df_all = df_all.drop_duplicates(subset=["platform", "post_id"]).reset_index(drop=True)
    else:
        df_all = df_new

    df_all.to_csv(path, index=False, encoding="utf-8")
    print(f"Saved {len(df_all)} total rows to {path}")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)

    df = collect_all(listing="new", limit_per_subreddit=100, sleep_sec=1.2)

    out_path = "data/reddit_raw.csv"
    save_incremental(df, out_path)