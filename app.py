import os
import re
from typing import List, Tuple


from flask import Flask, jsonify, request
from flask_cors import CORS
import psycopg

# OpenAI SDK v1
try:
    from openai import OpenAI
except Exception as e:  # pragma: no cover
    OpenAI = None  # type: ignore

# Load environment variables from a local .env file if present (dev only)
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass


def get_db_connection():
    """
    Create and return a new PostgreSQL connection using the DATABASE_URL
    environment variable. This uses psycopg (v3).
    """
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is not set")
    return psycopg.connect(database_url)


def get_formatted_alerts(limit: int = 50) -> str:
    """
    Query the most recent alerts and format them as a numbered list.

    Expected alert columns: technique, severity, timestamp, user_name, rule, source_ip
    """
    rows: List[Tuple] = []
    query = (
        """
        SELECT technique, severity, timestamp, user_name, rule, source_ip
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT %s;
        """
    )

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (limit,))
                rows = cur.fetchall()
    except Exception as exc:  # pragma: no cover
        # Return a diagnostics string the model can still reason about
        return f"No alerts available. Database query failed: {exc}"

    if not rows:
        return "No alerts available."

    lines: List[str] = []
    for idx, (technique, severity, ts,user_name, rule, source_ip) in enumerate(rows, start=1):
        lines.append(
            f"{idx}. Type: {technique} | Severity: {severity} | Time: {ts} | User_Name:{user_name} | Rule:{rule} | IP:{source_ip}"
        )
    return "\n".join(lines)


def generate_alert_report(user_message: str, formatted_alerts: str | None = None) -> str:
    """
    Use OpenAI to generate a concise security report/summary. If formatted_alerts
    is provided, it will be included in the system context for the model.
    """
    if OpenAI is None:
        raise RuntimeError(
            "The OpenAI SDK is not installed. Please add 'openai>=1.0.0' to requirements."
        )

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set")

    client = OpenAI(api_key=api_key)

    include_alerts = bool(formatted_alerts and formatted_alerts.strip())

    system_prompt = (
        "You are an assistant for a SIEM platform. Provide clear, concise, and actionable security insights.\n"
        "Output MUST be beautiful, professional Markdown optimized for readability in a web UI.\n"
        "Formatting requirements:\n"
        "- Start with a bold title line with an emoji (e.g., 🚨 Security Report).\n"
        "- Use clear section headings: Summary, Critical Threats, Recommended Actions.\n"
        "- Add tasteful emojis/icons to improve scannability: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW; use 🛡️, 🧰, 🧭, 🧪 where helpful.\n"
        "- PRESENT ALERTS AS ACTION-ORIENTED BULLETS (no tables). For each alert, provide two bullets:\n"
        "  • Observation: <Type> — <Severity emoji+label> — <Time> — <User/IP> — <Rule>\n"
        "  • Action: A concrete next step (e.g., isolate host, block IP, collect evidence).\n"
        "- Group alerts by highest risk first (CRITICAL → HIGH → MEDIUM → LOW).\n"
        "- Keep bullets short and scannable; bold key terms sparingly.\n"
        "- End with a short callout/next-steps line beginning with 👉.\n"
    )

    if include_alerts:
        system_prompt += "\n\nHere are recent alerts (most recent first):\n" + formatted_alerts

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        temperature=0.2,
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": user_message,
            },
        ],
    )

    ai_text = response.choices[0].message.content if response.choices else ""
    return ai_text or "No response generated."


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)  # Enable CORS for development and cross-origin dashboards

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    @app.route("/chat", methods=["POST"])
    def chat():
        data = request.get_json(silent=True) or {}
        message = (data.get("message") or "").strip()

        if not message:
            return jsonify({"response": "Please provide a message."}), 400

        # If message indicates a report/alert request, pull alerts and include context
        triggers = re.search(r"\b(report|alert)\b", message, flags=re.IGNORECASE) is not None
        formatted_alerts = get_formatted_alerts() if triggers else None

        try:
            ai_text = generate_alert_report(message, formatted_alerts)
        except Exception as exc:  # pragma: no cover
            return jsonify({"response": f"Error: {exc}"}), 500

        return jsonify({"response": ai_text})

    return app


if __name__ == "__main__":
    # For local development. In production, run with a WSGI server (gunicorn/uwsgi).
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))



