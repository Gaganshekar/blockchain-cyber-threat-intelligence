import sqlite3
import json
import os
from datetime import datetime

from dotenv import load_dotenv


# ==================================================
# LOAD ENVIRONMENT VARIABLES
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ENV_FILE = os.path.join(
    BASE_DIR,
    ".env"
)

load_dotenv(ENV_FILE)


# ==================================================
# DATABASE CONFIGURATION
# ==================================================

DATABASE = os.path.join(
    BASE_DIR,
    "threats.db"
)

SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    ""
).strip()

SUPABASE_KEY = (
    os.getenv("SUPABASE_SECRET_KEY", "").strip()
    or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    or os.getenv("SUPABASE_KEY", "").strip()
    or os.getenv("SUPABASE_PUBLISHABLE_KEY", "").strip()
)

DATABASE_MODE = os.getenv(
    "DATABASE_MODE",
    ""
).strip().lower()


# ==================================================
# SUPABASE CLIENT
# ==================================================

_supabase_client = None


def _get_supabase_client():

    global _supabase_client

    if _supabase_client is not None:
        return _supabase_client

    if not SUPABASE_URL or not SUPABASE_KEY:

        raise RuntimeError(
            "Supabase configuration is missing. "
            "Set SUPABASE_URL and SUPABASE_SECRET_KEY "
            "(or SUPABASE_KEY)."
        )

    try:

        from supabase import create_client

        _supabase_client = create_client(
            SUPABASE_URL,
            SUPABASE_KEY
        )

        return _supabase_client

    except ImportError as e:

        raise RuntimeError(
            "The 'supabase' Python package is not installed."
        ) from e


# ==================================================
# DATABASE MODE
# ==================================================

def using_supabase():

    if DATABASE_MODE == "sqlite":
        return False

    if DATABASE_MODE == "supabase":
        return True

    return bool(
        SUPABASE_URL and SUPABASE_KEY
    )


# ==================================================
# SQLITE CONNECTION
# ==================================================

def get_connection():

    conn = sqlite3.connect(
        DATABASE
    )

    conn.row_factory = sqlite3.Row

    return conn


# ==================================================
# CREATE SQLITE TABLES
# ==================================================

def _create_sqlite_tables():

    conn = get_connection()

    cursor = conn.cursor()

    try:

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats(

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            title TEXT NOT NULL,

            category TEXT NOT NULL,

            severity TEXT NOT NULL,

            indicator TEXT NOT NULL UNIQUE,

            description TEXT NOT NULL,

            reporter TEXT NOT NULL,

            status TEXT DEFAULT 'Unknown',

            risk_score INTEGER DEFAULT 0,

            confidence INTEGER DEFAULT 0,

            block_index INTEGER,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blockchain(

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            block_index INTEGER UNIQUE,

            timestamp TEXT,

            previous_hash TEXT,

            current_hash TEXT,

            nonce INTEGER,

            data TEXT

        )
        """)

        conn.commit()

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# CREATE DATABASE TABLES
# ==================================================

def create_table():

    if using_supabase():

        # Supabase tables already exist.
        #
        # IMPORTANT:
        # Do not recreate, migrate, delete, or
        # overwrite existing Supabase records.

        return True

    _create_sqlite_tables()

    return True


# ==================================================
# SUPABASE RESPONSE DATA
# ==================================================

def _response_data(response):

    if response is None:
        return []

    data = getattr(
        response,
        "data",
        None
    )

    if data is None:
        return []

    return data


# ==================================================
# ADD THREAT
# ==================================================

def add_threat(
    title,
    category,
    severity,
    indicator,
    description,
    reporter,
    status="Unknown",
    risk_score=0,
    confidence=0
):

    if using_supabase():

        client = _get_supabase_client()

        payload = {
            "title": title,
            "category": category,
            "severity": severity,
            "indicator": indicator,
            "description": description,
            "reporter": reporter,
            "status": status,
            "risk_score": risk_score,
            "confidence": confidence
        }

        response = (
            client
            .table("threats")
            .insert(payload)
            .execute()
        )

        data = _response_data(response)

        if not data:
            return None

        return data[0].get("id")

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        INSERT INTO threats
        (
            title,
            category,
            severity,
            indicator,
            description,
            reporter,
            status,
            risk_score,
            confidence
        )
        VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (
            title,
            category,
            severity,
            indicator,
            description,
            reporter,
            status,
            risk_score,
            confidence
        ))

        threat_id = cursor.lastrowid

        conn.commit()

        return threat_id

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# SAVE BLOCK
# ==================================================

def save_block(
    block_index,
    previous_hash,
    current_hash,
    nonce,
    timestamp,
    data=None
):

    block_data = (
        json.dumps(data)
        if data is not None
        else None
    )

    if using_supabase():

        client = _get_supabase_client()

        payload = {
            "block_index": block_index,
            "timestamp": str(timestamp),
            "previous_hash": previous_hash,
            "current_hash": current_hash,
            "nonce": nonce,
            "data": block_data
        }

        try:

            (
                client
                .table("blockchain")
                .insert(payload)
                .execute()
            )

        except Exception as e:

            message = str(e).lower()

            if (
                "duplicate" in message
                or "unique" in message
                or "23505" in message
            ):
                return False

            raise

        return True

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        INSERT INTO blockchain
        (
            block_index,
            timestamp,
            previous_hash,
            current_hash,
            nonce,
            data
        )
        VALUES(?,?,?,?,?,?)
        """,
        (
            block_index,
            str(timestamp),
            previous_hash,
            current_hash,
            nonce,
            block_data
        ))

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        return False

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# SAVE THREAT AND BLOCK
# ==================================================

def save_threat_and_block(
    title,
    category,
    severity,
    indicator,
    description,
    reporter,
    status,
    risk_score,
    confidence,
    block
):

    if using_supabase():

        client = _get_supabase_client()

        threat_payload = {
            "title": title,
            "category": category,
            "severity": severity,
            "indicator": indicator,
            "description": description,
            "reporter": reporter,
            "status": status,
            "risk_score": risk_score,
            "confidence": confidence,
            "block_index": block.index,
            "created_at": block.timestamp
        }

        block_payload = {
            "block_index": block.index,
            "timestamp": str(block.timestamp),
            "previous_hash": block.previous_hash,
            "current_hash": block.hash,
            "nonce": block.nonce,
            "data": json.dumps(block.data)
        }

        threat_response = (
            client
            .table("threats")
            .insert(threat_payload)
            .execute()
        )

        threat_data = _response_data(
            threat_response
        )

        if not threat_data:

            raise RuntimeError(
                "Threat could not be saved to Supabase."
            )

        (
            client
            .table("blockchain")
            .insert(block_payload)
            .execute()
        )

        return True

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
            INSERT INTO threats
            (
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
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                title,
                category,
                severity,
                indicator,
                description,
                reporter,
                status,
                risk_score,
                confidence,
                block.index,
                block.timestamp
            ))

        cursor.execute("""
        INSERT OR IGNORE INTO blockchain
        (
            block_index,
            timestamp,
            previous_hash,
            current_hash,
            nonce,
            data
        )
        VALUES (?,?,?,?,?,?)
        """,
        (
            block.index,
            str(block.timestamp),
            block.previous_hash,
            block.hash,
            block.nonce,
            json.dumps(block.data)
        ))

        conn.commit()

        return True

    except Exception as e:

        conn.rollback()
        raise e

    finally:

        conn.close()


# ==================================================
# UPDATE BLOCK INDEX
# ==================================================

def update_block_index(
    threat_id,
    block_index
):

    if using_supabase():

        client = _get_supabase_client()

        (
            client
            .table("threats")
            .update({
                "block_index": block_index
            })
            .eq("id", threat_id)
            .execute()
        )

        return True

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        UPDATE threats
        SET block_index=?
        WHERE id=?
        """,
        (
            block_index,
            threat_id
        ))

        conn.commit()

        return True

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# GET ALL THREATS
# ==================================================

def get_all_threats():

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("threats")
            .select("*")
            .order("block_index", desc=False)
            .execute()
        )

        return _response_data(response)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM threats
    ORDER BY block_index ASC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


# ==================================================
# GET ALL BLOCKS
# ==================================================

def get_all_blocks():

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("blockchain")
            .select("*")
            .order(
                "block_index",
                desc=False
            )
            .execute()
        )

        return _response_data(response)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM blockchain
    ORDER BY block_index ASC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


# ==================================================
# GET THREAT
# ==================================================

def get_threat(threat_id):

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("threats")
            .select("*")
            .eq("id", threat_id)
            .limit(1)
            .execute()
        )

        data = _response_data(response)

        if not data:
            return None

        return data[0]

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM threats
    WHERE id=?
    """,
    (
        threat_id,
    ))

    row = cursor.fetchone()

    conn.close()

    return row


# ==================================================
# GET BLOCK
# ==================================================

def get_block(block_index):

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("blockchain")
            .select("*")
            .eq(
                "block_index",
                block_index
            )
            .limit(1)
            .execute()
        )

        data = _response_data(response)

        if not data:
            return None

        return data[0]

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM blockchain
    WHERE block_index=?
    """,
    (
        block_index,
    ))

    row = cursor.fetchone()

    conn.close()

    return row


# ==================================================
# COUNT THREATS
# ==================================================

def count_threats():

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("threats")
            .select(
                "id",
                count="exact"
            )
            .execute()
        )

        count = getattr(
            response,
            "count",
            None
        )

        if count is not None:
            return count

        return len(
            _response_data(response)
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT COUNT(*)
    FROM threats
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total


# ==================================================
# COUNT BLOCKS
# ==================================================

def count_blocks():

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("blockchain")
            .select(
                "id",
                count="exact"
            )
            .execute()
        )

        count = getattr(
            response,
            "count",
            None
        )

        if count is not None:
            return count

        return len(
            _response_data(response)
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT COUNT(*)
    FROM blockchain
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total


# ==================================================
# SEARCH THREATS
# ==================================================

def search_threat(keyword):

    keyword = str(
        keyword or ""
    ).strip()

    if not keyword:
        return get_all_threats()

    if using_supabase():

        client = _get_supabase_client()

        search = f"%{keyword}%"

        response = (
            client
            .table("threats")
            .select("*")
            .or_(
                "title.ilike."
                + search
                + ",category.ilike."
                + search
                + ",severity.ilike."
                + search
                + ",indicator.ilike."
                + search
                + ",description.ilike."
                + search
                + ",reporter.ilike."
                + search
                + ",status.ilike."
                + search
            )
            .order(
                "id",
                desc=True
            )
            .execute()
        )

        return _response_data(response)

    conn = get_connection()
    cursor = conn.cursor()

    search = "%" + keyword + "%"

    cursor.execute("""
    SELECT *
    FROM threats
    WHERE
        title LIKE ?
        OR category LIKE ?
        OR severity LIKE ?
        OR indicator LIKE ?
        OR description LIKE ?
        OR reporter LIKE ?
        OR status LIKE ?
    ORDER BY id DESC
    """,
    (
        search,
        search,
        search,
        search,
        search,
        search,
        search
    ))

    rows = cursor.fetchall()

    conn.close()

    return rows


# ==================================================
# DELETE THREAT
# ==================================================

def delete_threat(threat_id):

    if using_supabase():

        client = _get_supabase_client()

        (
            client
            .table("threats")
            .delete()
            .eq(
                "id",
                threat_id
            )
            .execute()
        )

        return True

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        DELETE FROM threats
        WHERE id=?
        """,
        (
            threat_id,
        ))

        conn.commit()

        return True

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# DELETE BLOCK
# ==================================================

def delete_block(block_index):

    if using_supabase():

        client = _get_supabase_client()

        (
            client
            .table("blockchain")
            .delete()
            .eq(
                "block_index",
                block_index
            )
            .execute()
        )

        return True

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        DELETE FROM blockchain
        WHERE block_index=?
        """,
        (
            block_index,
        ))

        conn.commit()

        return True

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# CLEAR BLOCKCHAIN TABLE
# ==================================================

def clear_blockchain_table():

    if using_supabase():

        client = _get_supabase_client()

        (
            client
            .table("blockchain")
            .delete()
            .gte(
                "block_index",
                0
            )
            .execute()
        )

        (
            client
            .table("threats")
            .update({
                "block_index": None
            })
            .gte(
                "id",
                0
            )
            .execute()
        )

        return True

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        DELETE FROM blockchain
        """)

        cursor.execute("""
        UPDATE threats
        SET block_index=NULL
        """)

        conn.commit()

        return True

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# STATISTICS
# ==================================================

def get_statistics():

    statistics = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "safe": 0,
        "suspicious": 0,
        "malicious": 0,
        "blocks": 0
    }

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("threats")
            .select(
                "id,severity,status"
            )
            .execute()
        )

        threats = _response_data(response)

        statistics["total"] = len(
            threats
        )

        for threat in threats:

            severity = str(
                threat.get(
                    "severity",
                    ""
                )
            ).lower()

            status = str(
                threat.get(
                    "status",
                    ""
                )
            ).lower()

            if severity in statistics:
                statistics[severity] += 1

            if status in statistics:
                statistics[status] += 1

        response = (
            client
            .table("blockchain")
            .select(
                "id",
                count="exact"
            )
            .execute()
        )

        count = getattr(
            response,
            "count",
            None
        )

        if count is not None:
            statistics["blocks"] = count
        else:
            statistics["blocks"] = len(
                _response_data(response)
            )

        return statistics

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT COUNT(*)
    FROM threats
    """)

    statistics["total"] = (
        cursor.fetchone()[0]
    )

    for level in [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]:

        cursor.execute("""
        SELECT COUNT(*)
        FROM threats
        WHERE severity=?
        """,
        (
            level,
        ))

        statistics[
            level.lower()
        ] = cursor.fetchone()[0]

    for status in [
        "Safe",
        "Suspicious",
        "Malicious"
    ]:

        cursor.execute("""
        SELECT COUNT(*)
        FROM threats
        WHERE status=?
        """,
        (
            status,
        ))

        statistics[
            status.lower()
        ] = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM blockchain
    """)

    statistics["blocks"] = (
        cursor.fetchone()[0]
    )

    conn.close()

    return statistics


# ==================================================
# CLEAR COMPLETE DATABASE
# ==================================================

def clear_database():

    if using_supabase():

        client = _get_supabase_client()

        (
            client
            .table("blockchain")
            .delete()
            .gte(
                "block_index",
                0
            )
            .execute()
        )

        (
            client
            .table("threats")
            .delete()
            .gte(
                "id",
                0
            )
            .execute()
        )

        return True

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        DELETE FROM threats
        """)

        cursor.execute("""
        DELETE FROM blockchain
        """)

        conn.commit()

        return True

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# EXPORT DATA
# ==================================================

def export_data():

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("threats")
            .select("*")
            .order(
                "id",
                desc=False
            )
            .execute()
        )

        return _response_data(response)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM threats
    ORDER BY id ASC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


# ==================================================
# REBUILD BLOCKCHAIN DATA
# ==================================================

def rebuild_blockchain_data():

    return get_all_blocks()


# ==================================================
# BLOCK EXISTS
# ==================================================

def blockchain_block_exists(
    block_index
):

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("blockchain")
            .select("id")
            .eq(
                "block_index",
                block_index
            )
            .limit(1)
            .execute()
        )

        return bool(
            _response_data(response)
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT 1
    FROM blockchain
    WHERE block_index=?
    """,
    (
        block_index,
    ))

    result = cursor.fetchone()

    conn.close()

    return result is not None


# ==================================================
# LAST BLOCK INDEX
# ==================================================

def get_last_block_index():

    if using_supabase():

        client = _get_supabase_client()

        response = (
            client
            .table("blockchain")
            .select("block_index")
            .order(
                "block_index",
                desc=True
            )
            .limit(1)
            .execute()
        )

        blocks = _response_data(
            response
        )

        blockchain_max = 0

        if blocks:

            value = blocks[0].get(
                "block_index"
            )

            if value is not None:
                blockchain_max = int(value)

        response = (
            client
            .table("threats")
            .select("block_index")
            .not_.is_(
                "block_index",
                "null"
            )
            .order(
                "block_index",
                desc=True
            )
            .limit(1)
            .execute()
        )

        threats = _response_data(
            response
        )

        threat_max = 0

        if threats:

            value = threats[0].get(
                "block_index"
            )

            if value is not None:
                threat_max = int(value)

        return max(
            blockchain_max,
            threat_max
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT MAX(block_index)
    FROM blockchain
    """)

    value = cursor.fetchone()[0]

    cursor.execute("""
    SELECT MAX(block_index)
    FROM threats
    """)

    threat_value = cursor.fetchone()[0]

    conn.close()

    blockchain_max = (
        int(value)
        if value is not None
        else 0
    )

    threat_max = (
        int(threat_value)
        if threat_value is not None
        else 0
    )

    return max(
        blockchain_max,
        threat_max
    )


# ==================================================
# UPDATE THREAT ANALYSIS
# ==================================================

def update_threat_analysis(
    threat_id,
    status,
    risk_score,
    confidence
):

    if using_supabase():

        client = _get_supabase_client()

        (
            client
            .table("threats")
            .update({
                "status": status,
                "risk_score": risk_score,
                "confidence": confidence
            })
            .eq(
                "id",
                threat_id
            )
            .execute()
        )

        return True

    conn = get_connection()
    cursor = conn.cursor()

    try:

        cursor.execute("""
        UPDATE threats
        SET
            status=?,
            risk_score=?,
            confidence=?
        WHERE id=?
        """,
        (
            status,
            risk_score,
            confidence,
            threat_id
        ))

        conn.commit()

        return True

    except Exception:

        conn.rollback()
        raise

    finally:

        conn.close()


# ==================================================
# INITIALIZE
# ==================================================

if __name__ == "__main__":

    create_table()

    if using_supabase():

        print(
            "Supabase database selected."
        )

    else:

        print(
            "SQLite database selected."
        )