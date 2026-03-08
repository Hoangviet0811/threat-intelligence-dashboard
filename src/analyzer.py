import re
import math
import pandas as pd

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

KEYWORDS = {
    "ransomware": ["ransomware", "locker", "decryptor", "encryption"],
    "phishing": ["phishing", "credential", "spoof", "bec", "scam"],
    "exploit": [
        "exploit", "poc", "rce", "remote code execution",
        "privilege escalation", "zero-day", "0day",
        "in the wild", "active exploit"
    ],
    "malware": ["malware", "trojan", "stealer", "keylogger", "botnet", "loader"],
    "ddos": ["ddos", "amplification", "flood"],
    "leak": ["data leak", "breach", "dumped", "leaked", "paste"],
}

SEVERITY_RULES = [
    ("zero-day", 35),
    ("0day", 35),
    ("remote code execution", 30),
    ("rce", 30),
    ("in the wild", 25),
    ("active exploit", 25),
    ("poc", 15),
    ("exploit released", 15),
]

def normalize_text(title, selftext):
    text = f"{title} {selftext}".lower()
    text = re.sub(r"\s+", " ", text).strip()
    return text

def detect_attack_type(text):
    hits = {}
    for category, words in KEYWORDS.items():
        hits[category] = sum(1 for w in words if w in text)

    priority = ["exploit", "ransomware", "malware", "phishing", "leak", "ddos"]
    best = "other"
    best_score = 0

    for category in priority:
        if hits.get(category, 0) > best_score:
            best_score = hits[category]
            best = category

    return best

def calculate_severity(text, score, num_comments, has_cve):
    severity = 0

    for phrase, weight in SEVERITY_RULES:
        if phrase in text:
            severity += weight

    if has_cve:
        severity += 10

    engagement = max(0, score) + max(0, num_comments)
    severity += int(10 * math.log1p(engagement))

    return min(100, severity)

def severity_label(score):
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    else:
        return "Low"

def analyze_posts(input_path="data/reddit_raw.csv", output_path="data/analyzed_posts.csv"):
    df = pd.read_csv(input_path)

    text_norm_list = []
    cve_list = []
    attack_type_list = []
    severity_score_list = []
    severity_label_list = []

    for _, row in df.iterrows():
        text = normalize_text(row.get("title", ""), row.get("selftext", ""))
        text_norm_list.append(text)

        cves_found = sorted(set(match.group(0).upper() for match in CVE_REGEX.finditer(text)))
        cve_str = ", ".join(cves_found)
        cve_list.append(cve_str)

        attack_type = detect_attack_type(text)
        attack_type_list.append(attack_type)

        sev_score = calculate_severity(
            text=text,
            score=row.get("score", 0),
            num_comments=row.get("num_comments", 0),
            has_cve=len(cves_found) > 0
        )
        severity_score_list.append(sev_score)
        severity_label_list.append(severity_label(sev_score))

    df["text_norm"] = text_norm_list
    df["cves"] = cve_list
    df["attack_type"] = attack_type_list
    df["severity_score"] = severity_score_list
    df["severity"] = severity_label_list

    df.to_csv(output_path, index=False, encoding="utf-8")
    print(f"Saved analyzed data to {output_path}")
    print(df[['title', 'attack_type', 'severity', 'cves']].head(10))

if __name__ == "__main__":
    analyze_posts()