import os
import sqlite3
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()


# ==========================================================
# CONFIGURATION
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SQLITE_DATABASE = os.path.join(BASE_DIR, "threats.db")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SECRET_KEY")


# ==========================================================
# CHECK CONFIGURATION
# ==========================================================

if not SUPABASE_URL:
    print("ERROR: SUPABASE_URL environment variable not found.")
    exit()

if not SUPABASE_KEY:
    print("ERROR: SUPABASE_SECRET_KEY environment variable not found.")
    exit()


print("Supabase URL found: True")
print("Supabase key found: True")


# ==========================================================
# CONNECT TO SUPABASE
# ==========================================================

try:
    supabase = create_client(
        SUPABASE_URL,
        SUPABASE_KEY
    )

    print("SUCCESS: Connected to Supabase!")

except Exception as e:
    print("SUPABASE CONNECTION ERROR:")
    print(e)
    exit()


# ==========================================================
# CONNECT TO SQLITE
# ==========================================================

try:

    sqlite_connection = sqlite3.connect(
        SQLITE_DATABASE
    )

    sqlite_connection.row_factory = sqlite3.Row

    print("SUCCESS: Connected to SQLite!")

except Exception as e:

    print("SQLITE CONNECTION ERROR:")
    print(e)
    exit()


# ==========================================================
# READ EXISTING THREATS
# ==========================================================

try:

    rows = sqlite_connection.execute(
        """
        SELECT
            id,
            title,
            category,
            severity,
            indicator,
            description,
            reporter,
            status,
            risk_score,
            confidence,
            block_index,
            created_at
        FROM threats
        ORDER BY id
        """
    ).fetchall()

    print()
    print("SQLite threats found:", len(rows))

except Exception as e:

    print("ERROR READING SQLITE THREATS:")
    print(e)

    sqlite_connection.close()
    exit()


# ==========================================================
# STOP IF NO DATA
# ==========================================================

if not rows:

    print("No threats found in SQLite.")

    sqlite_connection.close()
    exit()


# ==========================================================
# CONVERT SQLITE ROWS TO POSTGRES DATA
# ==========================================================

threats = []

for row in rows:

    threat = {
        "id": row["id"],
        "title": row["title"],
        "category": row["category"],
        "severity": row["severity"],
        "indicator": row["indicator"],
        "description": row["description"],
        "reporter": row["reporter"],
        "status": row["status"],
        "risk_score": row["risk_score"],
        "confidence": row["confidence"],
        "block_index": row["block_index"],
        "created_at": row["created_at"]
    }

    threats.append(threat)


# ==========================================================
# SHOW MIGRATION PREVIEW
# ==========================================================

print()
print("Migration preview:")
print("------------------")

for threat in threats:

    print(
        f"ID: {threat['id']} | "
        f"Title: {threat['title']} | "
        f"Indicator: {threat['indicator']} | "
        f"Block: {threat['block_index']}"
    )


# ==========================================================
# ASK FOR CONFIRMATION
# ==========================================================

print()
print("About to migrate", len(threats), "threats to Supabase.")

confirmation = input(
    "Type MIGRATE to continue: "
).strip()


if confirmation != "MIGRATE":

    print()
    print("Migration cancelled.")

    sqlite_connection.close()

    exit()


# ==========================================================
# INSERT DATA INTO SUPABASE
# ==========================================================

print()
print("Starting migration...")
print()


success_count = 0
failed_count = 0


for threat in threats:

    try:

        # Check whether this ID already exists
        existing = (
            supabase
            .table("threats")
            .select("id")
            .eq("id", threat["id"])
            .execute()
        )

        if existing.data:

            print(
                f"SKIPPED: ID {threat['id']} "
                f"already exists."
            )

            continue


        # Insert threat
        response = (
            supabase
            .table("threats")
            .insert(threat)
            .execute()
        )


        if response.data:

            print(
                f"MIGRATED: "
                f"ID {threat['id']} - "
                f"{threat['title']}"
            )

            success_count += 1

        else:

            print(
                f"FAILED: "
                f"ID {threat['id']}"
            )

            failed_count += 1


    except Exception as e:

        print(
            f"ERROR: ID {threat['id']}"
        )

        print(e)

        failed_count += 1


# ==========================================================
# CLOSE SQLITE
# ==========================================================

sqlite_connection.close()


# ==========================================================
# VERIFY SUPABASE
# ==========================================================

print()
print("==========================================")
print("MIGRATION SUMMARY")
print("==========================================")

print("SQLite records found:", len(rows))
print("Successfully migrated:", success_count)
print("Failed:", failed_count)


try:

    verification = (
        supabase
        .table("threats")
        .select("id", count="exact")
        .execute()
    )

    print(
        "Supabase threat count:",
        verification.count
    )

except Exception as e:

    print("Could not verify Supabase count.")
    print(e)


print()
print("Original SQLite database was NOT modified.")
print("Migration process completed.")