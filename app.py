
import os
import re
import ipaddress
import threading
import webbrowser

from urllib.parse import urlparse

from flask import (
    Flask,
    json,
    render_template,
    render_template_string,
    request,
    redirect,
    jsonify,
    flash
)

import database
from blockchain import Blockchain
from threat_checker import ThreatChecker
from flask import render_template_string
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")

import blockchain


# ==================================================
# FLASK CONFIGURATION
# ==================================================
app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "cyber_threat_secret_key"
)


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

database.create_table()


# ==================================================
# BLOCKCHAIN INITIALIZATION
# ==================================================

blockchain = Blockchain()


# ==================================================
# THREAT CHECKER INITIALIZATION
# ==================================================

checker = ThreatChecker()


# ==================================================
# INVALID THREAT WORDS
# ==================================================

INVALID_WORDS = {
    "hi",
    "hello",
    "hey",
    "test",
    "testing",
    "abc",
    "xyz",
    "sample",
    "nothing",
    "random"
}


# ==================================================
# VALIDATE THREAT TITLE
# ==================================================

def validate_threat_name(title):

    title = str(title or "").strip()

    if len(title) < 5:
        return False

    if len(title) > 100:
        return False

    if title.lower() in INVALID_WORDS:
        return False

    if title.isdigit():
        return False

    pattern = r"^[A-Za-z0-9 ._()\-]+$"

    return re.fullmatch(
        pattern,
        title
    ) is not None


# ==================================================
# VALIDATE IP
# ==================================================

def validate_ip(value):

    value = str(value or "").strip()

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


# ==================================================
# VALIDATE EMAIL
# ==================================================

def validate_email(value):

    value = str(value or "").strip()

    pattern = (
        r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
        r"@"
        r"[A-Za-z0-9-]+"
        r"(?:\.[A-Za-z0-9-]+)+$"
    )

    return re.fullmatch(
        pattern,
        value
    ) is not None


# ==================================================
# VALIDATE DOMAIN
# ==================================================

def validate_domain(value):

    value = str(value or "").strip().lower()

    # Domain should not contain protocol
    if "://" in value:
        return False

    # Domain should not contain @
    if "@" in value:
        return False

    # Remove trailing dot
    if value.endswith("."):
        value = value[:-1]

    if len(value) > 253:
        return False

    pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[A-Za-z]{2,63}$"
    )

    return re.fullmatch(
        pattern,
        value
    ) is not None


# ==================================================
# VALIDATE URL
# ==================================================

def validate_url(value):

    value = str(value or "").strip()

    try:

        parsed = urlparse(value)

        if parsed.scheme.lower() not in {
            "http",
            "https"
        }:
            return False

        if not parsed.netloc:
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        # IP URL
        if validate_ip(hostname):
            return True

        # Domain URL
        return validate_domain(hostname)

    except Exception:
        return False


# ==================================================
# VALIDATE SHA256
# ==================================================

def validate_sha256(value):

    value = str(value or "").strip()

    return bool(
        re.fullmatch(
            r"[A-Fa-f0-9]{64}",
            value
        )
    )


# ==================================================
# VALIDATE INDICATOR
# ==================================================

def validate_indicator(value):

    value = str(value or "").strip()

    return (
        validate_email(value)
        or validate_ip(value)
        or validate_url(value)
        or validate_domain(value)
        or validate_sha256(value)
    )


# ==================================================
# DETECT INDICATOR TYPE
# ==================================================

def detect_indicator_type(value):

    value = str(value or "").strip()

    if validate_email(value):
        return "email"

    if validate_ip(value):
        return "ip"

    if validate_url(value):
        return "url"

    if validate_domain(value):
        return "domain"

    if validate_sha256(value):
        return "hash"

    return "unknown"


# ==================================================
# FORM DATA HELPER
# ==================================================

def get_threat_form_data():

    return {
        "title": request.form.get(
            "title",
            ""
        ).strip(),

        "category": request.form.get(
            "category",
            ""
        ).strip(),

        "severity": request.form.get(
            "severity",
            ""
        ).strip(),

        "indicator": request.form.get(
            "indicator",
            ""
        ).strip(),

        "description": request.form.get(
            "description",
            ""
        ).strip(),

        "reporter": request.form.get(
            "reporter",
            ""
        ).strip()
    }


# ==================================================
# RENDER SUBMIT FORM WITH DATA
# ==================================================

def render_submit_form(data):

    return render_template(
        "submit.html",
        title=data.get("title", ""),
        category=data.get("category", ""),
        severity=data.get("severity", ""),
        indicator=data.get("indicator", ""),
        description=data.get("description", ""),
        reporter=data.get("reporter", "")
    )
def rebuild_blockchain():

    global blockchain

    blockchain = Blockchain()

    try:
        threats = database.get_all_threats()
    except Exception:
        return

    try:
        database.clear_blockchain_table()
    except Exception:
        return

    seen = set()

    for threat in threats:

        key = (
            threat["title"],
            threat["indicator"]
        )

        if key in seen:
            continue

        seen.add(key)

        block_data = {
            "title": threat["title"],
            "category": threat["category"],
            "severity": threat["severity"],
            "indicator": threat["indicator"],
            "description": threat["description"],
            "reporter": threat["reporter"]
        }

        try:

            timestamp = threat.get("created_at")

            block = blockchain.add_block(
                block_data,
                timestamp=timestamp
            )

            database.save_block(
                block.index,
                block.previous_hash,
                block.hash,
                block.nonce,
                block.timestamp,
                block.data
            )

            database.update_block_index(
                threat["id"],
                block.index
            )

        except Exception:
            continue
    # --------------------------------------------------
    # Get threats from database
    # --------------------------------------------------

    try:

        threats = database.get_all_threats()

        print(
            "THREATS FOUND:",
            len(threats)
        )

    except Exception as error:

        print(
            "BLOCKCHAIN REBUILD DATABASE ERROR:",
            error
        )

        return

    # --------------------------------------------------
    # Clear stored blockchain
    # --------------------------------------------------

    try:

        database.clear_blockchain_table()

    except Exception as error:

        print(
            "BLOCKCHAIN CLEAR ERROR:",
            error
        )

        return

    # --------------------------------------------------
    # Rebuild blocks
    # --------------------------------------------------

    seen = set()

    for threat in threats:

        key = (
            threat["title"],
            threat["indicator"]
        )

        if key in seen:

            continue

        seen.add(key)

        block_data = {

            "title":
                threat["title"],

            "category":
                threat["category"],

            "severity":
                threat["severity"],

            "indicator":
                threat["indicator"],

            "description":
                threat["description"],

            "reporter":
                threat["reporter"]
        }

        try:

            # --------------------------------------------------
            # Preserve original database timestamp
            # --------------------------------------------------

            timestamp = threat.get(
                "created_at"
            )


            block = blockchain.add_block(

                block_data,

                timestamp=timestamp
            )

            database.save_block(

                block.index,

                block.previous_hash,

                block.hash,

                block.nonce,

                block.timestamp,

                block.data
            )

            database.update_block_index(

                threat["id"],

                block.index
            )

        except Exception as error:

            print(
                "BLOCKCHAIN REBUILD BLOCK ERROR:",
                repr(error)
            )

    print()
    print("=" * 70)
    print(
        "BLOCKCHAIN REBUILD COMPLETE"
    )
    print(
        "TOTAL BLOCKS:",
        len(blockchain.chain)
    )
    print(
        "VALID:",
        blockchain.is_chain_valid()
    )
    print("=" * 70)
    print()
# ==================================================
# HOME PAGE
# ==================================================

@app.route("/")
def home():

    threats = database.get_all_threats()

    # Show only latest 10 threats on home page
    recent_threats = threats[:10]

    total = len(threats)

    return render_template(
        "index.html",
        threats=recent_threats,
        total=total,
        blockchain_blocks=len(
            database.get_all_blocks()
        ),
        blockchain_valid=blockchain.is_chain_valid()
    )
# ==================================================
# ABOUT PAGE
# ==================================================

@app.route("/about")
def about():

    return render_template(
        "about.html"
    )


# ==================================================
# THREAT CHECKER PAGE
# ==================================================

@app.route("/checker")
def checker_page():

    return render_template(
        "checker.html"
    )


# ==================================================
# CHECK THREAT
# ==================================================

@app.route(
    "/check",
    methods=["POST"]
)
def check_threat():

    indicator_type = request.form.get(
        "type",
        ""
    ).strip().lower()

    value = request.form.get(
        "value",
        ""
    ).strip()

    # --------------------------------------------------
    # Allow automatic detection if type is missing
    # --------------------------------------------------

    if not indicator_type:

        indicator_type = detect_indicator_type(
            value
        )

    # --------------------------------------------------
    # Empty indicator
    # --------------------------------------------------

    if not value:

        flash(
            "Please enter an indicator.",
            "danger"
        )

        return render_template(
            "checker.html"
        )

    # --------------------------------------------------
    # Validate indicator
    # --------------------------------------------------

    detected_type = detect_indicator_type(
        value
    )

    if detected_type == "unknown":

        flash(
            (
                f"'{value}' is not a valid "
                "IP address, URL, domain, email "
                "or SHA-256 hash."
            ),
            "danger"
        )

        return render_template(
            "checker.html",
            result=None
        )

    # Always trust actual detected type
    indicator_type = detected_type

    # --------------------------------------------------
    # Optional fields
    #
    # This allows checker.html to send additional
    # information if those fields exist.
    # --------------------------------------------------

    title = request.form.get(
        "title",
        ""
    ).strip()

    category = request.form.get(
        "category",
        ""
    ).strip()

    severity = request.form.get(
        "severity",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    # --------------------------------------------------
    # Threat analysis
    # --------------------------------------------------

    try:

        result = checker.check(
            indicator_type,
            value,
            title=title,
            category=category,
            severity=severity,
            description=description
        )

    except Exception as error:

        print(
            "THREAT CHECKER ERROR:",
            error
        )

        flash(
            "Threat analysis failed. Please try again.",
            "danger"
        )

        return render_template(
            "checker.html"
        )

    return render_template(
        "checker.html",
        result=result
    )


# ==================================================
# SUBMIT THREAT
# ==================================================

@app.route(
    "/submit",
    methods=["GET", "POST"]
)
def submit_page():

    # --------------------------------------------------
    # GET
    # --------------------------------------------------

    if request.method == "GET":

        return render_template(
            "submit.html"
        )

    # --------------------------------------------------
    # Read form data
    # --------------------------------------------------

    data = get_threat_form_data()

    title = data["title"]
    category = data["category"]
    severity = data["severity"]
    indicator = data["indicator"]
    description = data["description"]
    reporter = data["reporter"]

    # ==================================================
    # VALIDATE TITLE
    # ==================================================

    if not title:

        flash(
            "Threat title is required.",
            "danger"
        )

        return render_submit_form(data)

    if not validate_threat_name(title):

        flash(
            (
                "Invalid threat title. "
                "Use 5-100 characters and avoid "
                "test or meaningless values."
            ),
            "danger"
        )

        return render_submit_form(data)

    # ==================================================
    # VALIDATE CATEGORY
    # ==================================================

    if not category:

        flash(
            "Please select a threat category.",
            "danger"
        )

        return render_submit_form(data)

    # ==================================================
    # VALIDATE SEVERITY
    # ==================================================

    valid_severities = {
        "low",
        "medium",
        "high",
        "critical"
    }

    if severity.lower() not in valid_severities:

        flash(
            (
                "Invalid severity. "
                "Choose Low, Medium, High or Critical."
            ),
            "danger"
        )

        return render_submit_form(data)

    # ==================================================
    # VALIDATE INDICATOR
    # ==================================================

    if not indicator:

        flash(
            "Threat indicator is required.",
            "danger"
        )

        return render_submit_form(data)

    # --------------------------------------------------
    # Detect type
    # --------------------------------------------------

    indicator_type = detect_indicator_type(
        indicator
    )

    # --------------------------------------------------
    # Invalid indicator
    # --------------------------------------------------

    if indicator_type == "unknown":

        flash(
            (
                f"'{indicator}' is not valid. "
                "Use an IP address, URL, domain, "
                "email address or SHA-256 hash."
            ),
            "danger"
        )

        return render_submit_form(data)

    # ==================================================
    # DUPLICATE CHECK
    # ==================================================

    try:

        threats = database.get_all_threats()

    except Exception as error:

        print(
            "DATABASE READ ERROR:",
            error
        )

        flash(
            (
                "Unable to check existing threats. "
                "Database error occurred."
            ),
            "danger"
        )

        return render_submit_form(data)

    for threat in threats:

        existing_indicator = str(
            threat["indicator"]
        ).strip().lower()

        if existing_indicator == indicator.lower():

            flash(
                (
                    "Submission rejected: this threat "
                    "indicator already exists in the database."
                ),
                "warning"
            )

            return render_submit_form(data)

    # ==================================================
    # THREAT ANALYSIS
    # ==================================================

    try:

        analysis = checker.check(
            indicator_type,
            indicator,
            title=title,
            category=category,
            severity=severity,
            description=description
        )

    except Exception as error:

        print(
            "THREAT ANALYSIS ERROR:",
            error
        )

        flash(
            (
                "Threat analysis failed. "
                "The submission was not saved."
            ),
            "danger"
        )

        return render_submit_form(data)

    status = analysis.get(
        "status",
        "Unknown"
    )

    score = analysis.get(
        "score",
        0
    )

    confidence = analysis.get(
        "confidence",
        0
    )

    reason = analysis.get(
        "reason",
        "No additional reason available."
    )

    print()
    print("=" * 60)
    print("THREAT ANALYSIS")
    print("=" * 60)
    print("Indicator :", indicator)
    print("Type      :", indicator_type)
    print("Status    :", status)
    print("Score     :", score)
    print("Confidence:", confidence)
    print("Reason    :", reason)
    print("=" * 60)

    # ==================================================
    # CREATE BLOCKCHAIN BLOCK
    # ==================================================

    try:

        block = blockchain.add_block({

            "title": title,

            "category": category,

            "severity": severity,

            "indicator": indicator,

            "description": description,

            "reporter": reporter

        })

    except Exception as error:

        print(
            "BLOCKCHAIN ERROR:",
            error
        )

        flash(
            (
                "Submission failed: unable to create "
                "blockchain record."
            ),
            "danger"
        )

        return render_submit_form(data)

    # ==================================================
    # SAVE TO DATABASE
    # ==================================================

    try:

        database.save_threat_and_block(
            title,
            category,
            severity,
            indicator,
            description,
            reporter,
            status,
            score,
            confidence,
            block
        )

    except Exception as error:

        print()
        print("=" * 60)
        print("DATABASE ERROR")
        print(error)
        print("=" * 60)

        # The block was already created.
        # Rebuild from the database to remove the
        # unsaved blockchain block from memory.

        try:

            rebuild_blockchain()

        except Exception as rebuild_error:

            print(
                "BLOCKCHAIN ROLLBACK ERROR:",
                rebuild_error
            )

        error_message = str(error).lower()

        if (
            "unique" in error_message
            or "duplicate" in error_message
        ):

            message = (
                "Submission failed: this threat "
                "already exists."
            )

        elif "database" in error_message:

            message = (
                "Submission failed: database error "
                "occurred while saving the threat."
            )

        else:

            message = (
                "Submission failed: the threat could "
                "not be saved to the database."
            )

        flash(
            message,
            "danger"
        )

        return render_submit_form(data)

    # ==================================================
    # SUCCESS LOG
    # ==================================================

    print()
    print("=" * 60)
    print("NEW THREAT SAVED")
    print("=" * 60)
    print("TITLE      :", title)
    print("CATEGORY   :", category)
    print("SEVERITY   :", severity)
    print("INDICATOR  :", indicator)
    print("TYPE       :", indicator_type)
    print("STATUS     :", status)
    print("SCORE      :", score)
    print("CONFIDENCE :", confidence)
    print("BLOCK      :", block.index)
    print("HASH       :", block.hash)
    print("=" * 60)

    # ==================================================
    # SUCCESS PAGE
    # ==================================================

    return render_template(
        "submit_success.html",

        threat={

            "title": title,

            "category": category,

            "severity": severity,

            "indicator": indicator,

            "description": description,

            "reporter": reporter,

            "status": status,

            "score": score,

            "confidence": confidence,

            "reason": reason,

            "indicator_type": indicator_type

        },

        block={

            "index": block.index,

            "timestamp": block.timestamp,

            "hash": block.hash,

            "previous_hash": block.previous_hash

        }
    )


# ==================================================
# REPORTS PAGE
# ==================================================

@app.route("/reports")
def reports():

    threats = database.get_all_threats()

    unique = []
    seen = set()

    for threat in threats:

        key = (
            threat["title"],
            threat["indicator"]
        )

        if key in seen:
            continue


        unique.append(threat)
        seen.add(key)

    total = len(unique)

    high = 0
    medium = 0
    low = 0
    critical = 0

    safe = 0
    suspicious = 0
    malicious = 0

    for row in unique:

        severity = str(
            row["severity"] or ""
        ).lower()

        if severity == "critical":
            critical += 1

        elif severity == "high":
            high += 1

        elif severity == "medium":
            medium += 1

        elif severity == "low":
            low += 1

        status = str(
            row["status"] or ""
        ).lower()

        if status == "safe":
            safe += 1

        elif status == "suspicious":
            suspicious += 1

        elif status == "malicious":
            malicious += 1

    return render_template(
        "reports.html",

        threats=unique,

        total=total,

        high=high,

        medium=medium,

        low=low,

        critical=critical,

        safe=safe,

        suspicious=suspicious,

        malicious=malicious
    )

# ==================================================
# SEARCH
# ==================================================

@app.route(
    "/search",
    methods=["POST"]
)
def search():

    keyword = request.form.get(
        "keyword",
        ""
    ).strip()

    if keyword == "":

        flash(
            "Enter a search keyword.",
            "warning"
        )

        return redirect(
            "/reports"
        )

    try:

        threats = database.search_threat(
            keyword
        )

    except Exception as error:

        print(
            "SEARCH ERROR:",
            error
        )

        flash(
            "Search failed. Please try again.",
            "danger"
        )

        return redirect(
            "/reports"
        )

    return render_template(
        "reports.html",
        threats=threats,
        total=len(threats)
    )


# ==================================================
# DELETE THREAT
# ==================================================

@app.route(
    "/delete/<int:id>"
)
def delete(id):

    try:

        database.delete_threat(id)

        rebuild_blockchain()

        flash(
            "Threat deleted successfully.",
            "success"
        )

    except Exception as error:

        print(
            "DELETE ERROR:",
            error
        )

        flash(
            "Unable to delete the threat.",
            "danger"
        )

    return redirect(
        "/reports"
    )


# ==================================================
# BLOCKCHAIN PAGE
# ==================================================

@app.route("/blockchain")
def blockchain_page():

    try:

        rows = database.get_all_blocks()

        blocks = []

        for row in rows:

            data = row.get("data", {})

            if isinstance(data, str):

                try:
                    data = json.loads(data)

                except Exception:

                    data = {}

            if not isinstance(data, dict):
                data = {}

            blocks.append({
                "index": row.get("block_index", 0),
                "timestamp": row.get("timestamp", ""),
                "previous_hash": row.get("previous_hash", ""),
                "hash": row.get("current_hash", ""),
                "nonce": row.get("nonce", 0),
                "data": data
            })

        valid = blockchain.is_chain_valid()

        difficulty = blockchain.difficulty

    except Exception as error:

        print(
            "BLOCKCHAIN PAGE ERROR:",
            error
        )

        blocks = []

        valid = False

        difficulty = blockchain.difficulty

    return render_template(
        "blockchain.html",

        blockchain=blocks,

        valid=valid,

        total_blocks=len(blocks),

        difficulty=difficulty
    )
# ==================================================
# VERIFY BLOCKCHAIN
# ==================================================

@app.route("/verify")
def verify():

    try:

        valid = blockchain.is_chain_valid()

        if valid:

            flash(
                "Blockchain integrity verified successfully.",
                "success"
            )

        else:

            flash(
                "Blockchain verification failed. Chain integrity may be compromised.",
                "danger"
            )

    except Exception as error:

        print(
            "BLOCKCHAIN VERIFY ERROR:",
            error
        )

        flash(
            "Unable to verify blockchain integrity.",
            "danger"
        )

    return redirect(
        "/blockchain"
    )


# ==================================================
# RELOAD BLOCKCHAIN
# ==================================================

@app.route("/reload")
def reload_blockchain():

    try:

        rebuild_blockchain()

        flash(
            "Blockchain rebuilt successfully.",
            "success"
        )

    except Exception as error:

        print(
            "BLOCKCHAIN RELOAD ERROR:",
            error
        )

        flash(
            "Blockchain rebuild failed.",
            "danger"
        )

    return redirect(
        "/blockchain"
    )


# ==================================================
# BLOCKCHAIN API
# ==================================================

@app.route("/api/blockchain")
def api_blockchain():

    try:

        return jsonify({

            "valid":
                blockchain.is_chain_valid(),

            "length":
                len(blockchain.chain),

            "statistics":
                blockchain.get_statistics(),

            "chain":
                blockchain.get_chain()

        })

    except Exception as error:

        return jsonify({

            "error":
                "Unable to retrieve blockchain data.",

            "message":
                str(error)

        }), 500


# ==================================================
# THREATS API
# ==================================================

@app.route("/api/threats")
def api_threats():

    try:

        return jsonify({

            "count":
                database.count_threats(),

            "data":
                database.get_all_threats()

        })

    except Exception as error:

        return jsonify({

            "error":
                "Unable to retrieve threats.",

            "message":
                str(error)

        }), 500


# ==================================================
# PROJECT STATISTICS API
# ==================================================

@app.route("/stats")
def stats():

    try:

        threats = database.get_all_threats()
        blocks = database.get_all_blocks()

        # ==================================================
        # REMOVE DUPLICATE THREATS
        # ==================================================

        unique_threats = []
        seen = set()

        for row in threats:

            title = str(
                row["title"] or ""
            ).strip().lower()

            indicator = str(
                row["indicator"] or ""
            ).strip().lower()

            key = (
                title,
                indicator
            )

            if key in seen:
                continue

            seen.add(key)
            unique_threats.append(row)

        # ==================================================
        # STATISTICS
        # ==================================================

        result = {

            "total_reports":
                len(unique_threats),

            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,

            "safe": 0,
            "suspicious": 0,
            "malicious": 0,

            "phishing": 0,
            "malware": 0,
            "ransomware": 0,
            "trojan": 0,
            "spyware": 0,
            "ddos": 0,
            "botnet": 0,

            "blockchain_blocks":
                len(blocks),

            "blockchain_valid":
                blockchain.is_chain_valid()
        }

        # ==================================================
        # COUNT UNIQUE THREATS
        # ==================================================

        for row in unique_threats:

            severity = str(
                row["severity"] or ""
            ).strip().lower()

            category = str(
                row["category"] or ""
            ).strip().lower()

            status = str(
                row["status"] or ""
            ).strip().lower()

            if severity in result:
                result[severity] += 1

            if category in result:
                result[category] += 1

            if status in result:
                result[status] += 1

        return jsonify(result)

    except Exception as error:

        print(
            "STATS ERROR:",
            error
        )

        return jsonify({

            "error":
                "Unable to retrieve statistics",

            "message":
                str(error)

        }), 500
# ==================================================
# HEALTH API
# ==================================================

@app.route("/health")
def health():

    try:

        valid = blockchain.is_chain_valid()

        blocks = len(
            blockchain.chain
        )

        difficulty = blockchain.difficulty

    except Exception:

        valid = False
        blocks = 0
        difficulty = 0

    return jsonify({

        "application":
            "Blockchain Cyber Threat Intelligence Sharing",

        "status":
            "Running",

        "database":
            "Connected",

        "blockchain_valid":
            valid,

        "blocks":
            blocks,

        "difficulty":
            difficulty

    })


# ==================================================
# EXPORT BLOCKCHAIN
# ==================================================

@app.route("/export")
def export_blockchain():

    return jsonify({

        "valid":
            blockchain.is_chain_valid(),

        "length":
            len(blockchain.chain),

        "chain":
            blockchain.get_chain()

    })


# ==================================================
# THREATS PAGE
# ==================================================

@app.route("/threats")
def threats():

    return render_template(
        "threats.html",
        threats=database.get_all_threats()
    )


# ==================================================
# RESET DATABASE
# ==================================================

@app.route("/reset")
def reset():

    try:

        threats = database.get_all_threats()

        for row in threats:

            database.delete_threat(
                row["id"]
            )

        rebuild_blockchain()

        flash(
            "Database reset successfully.",
            "success"
        )

    except Exception as error:

        print(
            "RESET ERROR:",
            error
        )

        flash(
            "Database reset failed.",
            "danger"
        )

    return redirect(
        "/reports"
    )


# ==================================================
# CLEANUP DUPLICATES
# ==================================================

@app.route("/cleanup")
def cleanup():

    try:

        conn = database.get_connection()

        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM threats
            WHERE id NOT IN
            (
                SELECT MIN(id)
                FROM threats
                GROUP BY title, indicator
            )
        """)

        cursor.execute(
            "DELETE FROM blockchain"
        )

        conn.commit()

        conn.close()

        rebuild_blockchain()

        flash(
            "Duplicate threats cleaned successfully.",
            "success"
        )

    except Exception as error:

        print(
            "CLEANUP ERROR:",
            error
        )

        flash(
            "Cleanup failed.",
            "danger"
        )

    return redirect(
        "/reports"
    )


# ==================================================
# CLEAN BLOCKCHAIN
# ==================================================

@app.route("/clean_blockchain")
def clean_blockchain():

    global blockchain

    try:

        database.clear_blockchain_table()

        blockchain = Blockchain()

        flash(
            "Blockchain cleaned successfully.",
            "success"
        )

    except Exception as error:

        print(
            "CLEAN BLOCKCHAIN ERROR:",
            error
        )

        flash(
            "Unable to clean blockchain.",
            "danger"
        )

    return redirect(
        "/blockchain"
    )


# ==================================================
# RECALCULATE ALL THREAT SCORES
# ==================================================

@app.route("/recalculate_scores")
def recalculate_scores():

    threats = database.get_all_threats()

    updated = 0

    failed = 0

    for threat in threats:

        try:

            indicator = str(
                threat["indicator"] or ""
            ).strip()

            indicator_type = detect_indicator_type(
                indicator
            )

            if indicator_type == "unknown":

                failed += 1

                continue

            title = str(
                threat["title"] or ""
            ).strip()

            category = str(
                threat["category"] or ""
            ).strip()

            severity = str(
                threat["severity"] or ""
            ).strip()

            description = str(
                threat["description"] or ""
            ).strip()

            analysis = checker.check(

                indicator_type,

                indicator,

                title=title,

                category=category,

                severity=severity,

                description=description

            )

            database.update_threat_analysis(

                threat["id"],

                analysis["status"],

                analysis["score"],

                analysis["confidence"]

            )

            updated += 1

        except Exception as error:

            failed += 1

            print(
                "SCORE RECALCULATION ERROR:",
                error
            )

    return jsonify({

        "message":
            "Threat scores recalculated.",

        "updated":
            updated,

        "failed":
            failed,

        "total":
            len(threats)

    })


# ==================================================
# FAVICON
# ==================================================

@app.route("/favicon.ico")
def favicon():

    return "", 204


# ==================================================
# ERROR HANDLERS
# ==================================================

@app.errorhandler(404)
def page_not_found(error):

    return jsonify({

        "error":
            "Page Not Found",

        "status":
            404

    }), 404


@app.errorhandler(500)
def internal_error(error):

    print(
        "INTERNAL SERVER ERROR:",
        error
    )

    return jsonify({

        "error":
            "Internal Server Error",

        "message":
            "An unexpected server error occurred."

    }), 500


# ==================================================
# OPEN BROWSER
# ==================================================

def open_browser():

    url = "http://127.0.0.1:5000"

    brave_paths = [

        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",

        r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe"

    ]

    for path in brave_paths:

        if os.path.exists(path):

            try:

                webbrowser.register(

                    "brave",

                    None,

                    webbrowser.BackgroundBrowser(
                        path
                    )

                )

                webbrowser.get(
                    "brave"
                ).open(url)

                return

            except Exception as error:

                print(
                    "BRAVE OPEN ERROR:",
                    error
                )

    try:

        webbrowser.open(url)

    except Exception as error:

        print(
            "BROWSER OPEN ERROR:",
            error
        )
# ==================================================
# DATETIME FORMATTER
# ==================================================

# ==================================================
# DATETIME FORMATTER - UTC TO IST
# ==================================================

from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")


def convert_to_ist(value):

    if not value:
        return ""

    try:

        value = str(value).strip()

        # ------------------------------------------
        # ISO format
        # Example:
        # 2026-08-03T09:21:40+00:00
        # ------------------------------------------

        if "T" in value:

            dt = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

        # ------------------------------------------
        # SQLite CURRENT_TIMESTAMP
        # Example:
        # 2026-08-03 09:21:40
        # ------------------------------------------

        else:

            dt = datetime.strptime(
                value,
                "%Y-%m-%d %H:%M:%S"
            )

        # ------------------------------------------
        # Database timestamps are UTC
        # ------------------------------------------

        if dt.tzinfo is None:

            dt = dt.replace(
                tzinfo=timezone.utc
            )

        # ------------------------------------------
        # UTC -> IST
        # ------------------------------------------

        dt = dt.astimezone(IST)

        return dt.strftime(
            "%d %b %Y, %I:%M %p"
        )

    except Exception as error:

        print(
            "DATETIME FORMAT ERROR:",
            value,
            error
        )

        return str(value)


# Both names point to the same converter.
# This keeps old templates working too.
@app.route("/time-test")
def time_test():

    test_time = "2026-08-03T09:21:40+00:00"

    return render_template_string(
        """
        <h1>Datetime Test</h1>

        <p>RAW: {{ value }}</p>

        <p>FORMATTED: {{ value|display_datetime }}</p>
        """,
        value=test_time
    )
@app.template_filter("format_datetime")
def format_datetime(value):

    if not value:
        return ""

    try:
        value = str(value).strip()

        # Handle SQLite UTC format
        if "T" not in value and "+" not in value and "Z" not in value:
            dt = datetime.strptime(
                value,
                "%Y-%m-%d %H:%M:%S"
            )

            dt = dt.replace(
                tzinfo=timezone.utc
            )

        else:
            # Handle ISO timestamp
            dt = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

            if dt.tzinfo is None:
                dt = dt.replace(
                    tzinfo=timezone.utc
                )

        # Convert UTC to Indian Standard Time
        from zoneinfo import ZoneInfo

        ist = ZoneInfo("Asia/Kolkata")

        dt = dt.astimezone(ist)

        # Normal readable format
        return dt.strftime(
            "%d %b %Y, %I:%M %p"
        )

    except Exception as e:

        print(
            "DATETIME FORMAT ERROR:",
            value,
            e
        )

        return str(value)


    # ==================================================
# APPLICATION START
# ==================================================

if __name__ == "__main__":

    # Local development server
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
        use_reloader=False
    )