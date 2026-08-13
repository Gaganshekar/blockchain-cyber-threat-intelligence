import sqlite3
import json
import os
from datetime import datetime


# ==================================================
# DATABASE FILE
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(
    BASE_DIR,
    "threats.db"
)


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_connection():

    conn = sqlite3.connect(
        DATABASE
    )

    conn.row_factory = sqlite3.Row

    return conn





# ==================================================
# CREATE DATABASE TABLES
# ==================================================

def create_table():

    conn = get_connection()

    cursor = conn.cursor()



    # ------------------------------
    # THREATS TABLE
    # ------------------------------

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



    # ------------------------------
    # BLOCKCHAIN TABLE
    # ------------------------------

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

    conn.close()





# ==================================================
# ADD THREAT ONLY
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


        VALUES(?,?,?,?,?,?,?,?,?)

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
# SAVE BLOCKCHAIN BLOCK
# ==================================================

def save_block(

    block_index,

    previous_hash,

    current_hash,

    nonce,

    timestamp,

    data=None

):


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

            timestamp,

            previous_hash,

            current_hash,

            nonce,

            json.dumps(data)

            if data else None

        ))



        conn.commit()



    except sqlite3.IntegrityError:


        # Block already exists

        pass



    except Exception:


        conn.rollback()

        raise



    finally:


        conn.close()
        # ==================================================
# SAVE THREAT AND BLOCKCHAIN TOGETHER
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

    conn = get_connection()
    cursor = conn.cursor()

    try:

        # Save threat
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
            block_index
        )
        VALUES (?,?,?,?,?,?,?,?,?,?)
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
            block.index
        ))

        # Save blockchain
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
# UPDATE THREAT BLOCK INDEX
# ==================================================

def update_block_index(

    threat_id,

    block_index

):


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



    except Exception:


        conn.rollback()

        raise



    finally:


        conn.close()






# ==================================================
# GET ALL THREATS
# ==================================================

def get_all_threats():


    conn = get_connection()

    cursor = conn.cursor()



    cursor.execute("""

    SELECT *

    FROM threats

    ORDER BY id DESC

    """)



    rows = cursor.fetchall()



    conn.close()



    return rows





# ==================================================
# GET ALL BLOCKCHAIN BLOCKS
# ==================================================

def get_all_blocks():


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
# GET THREAT BY ID
# ==================================================

def get_threat(threat_id):


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
# GET BLOCK BY INDEX
# ==================================================

def get_block(block_index):


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
# COUNT BLOCKCHAIN BLOCKS
# ==================================================

def count_blocks():

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



    except Exception:


        conn.rollback()

        raise



    finally:


        conn.close()





# ==================================================
# DELETE BLOCKCHAIN BLOCK
# ==================================================

def delete_block(block_index):


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



    except Exception:


        conn.rollback()

        raise



    finally:


        conn.close()





# ==================================================
# CLEAR BLOCKCHAIN TABLE
# ==================================================

def clear_blockchain_table():


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



    except Exception:


        conn.rollback()

        raise



    finally:


        conn.close()





# ==================================================
# DASHBOARD STATISTICS
# ==================================================

def get_statistics():


    conn = get_connection()

    cursor = conn.cursor()



    statistics = {}



    # Total threats

    cursor.execute("""

    SELECT COUNT(*)

    FROM threats

    """)


    statistics["total"] = cursor.fetchone()[0]




    # Severity count

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



        statistics[level.lower()] = cursor.fetchone()[0]





    # Threat status count

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



        statistics[status.lower()] = cursor.fetchone()[0]





    # Blockchain blocks

    cursor.execute("""

    SELECT COUNT(*)

    FROM blockchain

    """)


    statistics["blocks"] = cursor.fetchone()[0]



    conn.close()



    return statistics
# ==================================================
# CLEAR COMPLETE DATABASE
# ==================================================

def clear_database():


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



    except Exception:


        conn.rollback()

        raise



    finally:


        conn.close()





# ==================================================
# EXPORT THREAT DATA
# ==================================================

def export_data():


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
# GET BLOCKCHAIN DATA FOR REBUILD
# ==================================================

def rebuild_blockchain_data():


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
# CHECK BLOCK EXISTS
# ==================================================

def blockchain_block_exists(block_index):


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
# GET LAST BLOCK INDEX
# ==================================================

def get_last_block_index():


    conn = get_connection()

    cursor = conn.cursor()



    cursor.execute("""

    SELECT MAX(block_index)

    FROM blockchain

    """)



    value = cursor.fetchone()[0]



    conn.close()



    if value is None:

        return 0



    return value

def update_threat_analysis(threat_id, status, risk_score, confidence):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE threats
        SET
            status = ?,
            risk_score = ?,
            confidence = ?
        WHERE id = ?
    """, (
        status,
        risk_score,
        confidence,
        threat_id
    ))

    conn.commit()
    conn.close()


# ==================================================
# INITIALIZE DATABASE
# ==================================================

if __name__ == "__main__":


    create_table()


    print(
        "Database Created Successfully"
    )

    