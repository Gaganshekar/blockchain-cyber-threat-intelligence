import sqlite3
from threat_checker import ThreatChecker

checker = ThreatChecker()

conn = sqlite3.connect("threats.db")
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

rows = cursor.execute("SELECT * FROM threats").fetchall()

updated = 0

for row in rows:

    title = row["title"]
    indicator = row["indicator"]

    # Detect indicator type
    if indicator.count(".") == 3:
        indicator_type = "ip"
    elif indicator.startswith("http://") or indicator.startswith("https://"):
        indicator_type = "url"
    elif "@" in indicator:
        indicator_type = "email"
    elif len(indicator) in (32, 40, 64):
        indicator_type = "hash"
    else:
        indicator_type = "domain"

    analysis = checker.check(indicator_type, indicator)

    # Check title for malicious words
    title_lower = title.lower()

    for keyword in checker.malicious_keywords:
        if keyword in title_lower:
            analysis["score"] = max(analysis["score"], 95)
            analysis["status"] = "Malicious"

    for keyword in checker.suspicious_keywords:
        if keyword in title_lower:
            analysis["score"] = max(analysis["score"], 60)
            if analysis["status"] != "Malicious":
                analysis["status"] = "Suspicious"

    cursor.execute("""
        UPDATE threats
        SET status=?,
            risk_score=?,
            confidence=?
        WHERE id=?
    """, (
        analysis["status"],
        analysis["score"],
        analysis["confidence"],
        row["id"]
    ))

    updated += 1

conn.commit()
conn.close()

print(f"{updated} threats updated successfully.")