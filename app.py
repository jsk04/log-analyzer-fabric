# app.py

import os
import sqlite3
import logging
import re
import gzip
import io
import csv
import pandas as pd
from collections import defaultdict
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import (
    Flask, request, render_template, session,
    redirect, url_for, jsonify, flash, send_file, Response
)
from authlib.integrations.flask_client import OAuth
from markupsafe import Markup, escape
import plotly.graph_objs as go
import plotly.io as pio
import bleach
from io import StringIO, BytesIO

load_dotenv()

# --- Configuration ---
LOG_DIR = "/LOCATION/OF/YOUR/QA-TOOL/LOG-FOLDER/"
DB_FILE = 'qa_log_entries.db'
AUTHORIZED_USERS_FILE = 'authorized_users.txt'
READONLY_USERS_FILE = 'authorized_users_read_only.txt'
TAGS_FILE = 'tags.txt'
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
UNAUTHORIZED_LOG_PATH = 'logs/unauthorized_access.log'
USER_LOGIN_LOG_PATH = 'logs/user_logins.log'
PER_PAGE = 50

# Allowed HTML tags/attributes for the response field
ALLOWED_TAGS = ['a', 'br', 'code', 'pre', 'em', 'strong', 'p', 'span']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target'],
    'span': ['style']
}

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- OAuth with CILogon ---
oauth = OAuth(app)
oauth.register(
    name='cilogon',
    client_id=os.getenv('CILOGON_CLIENT_ID'),
    client_secret=os.getenv('CILOGON_CLIENT_SECRET'),
    server_metadata_url='https://cilogon.org/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email org.cilogon.userinfo'}
)

# Ensure log directory exists
os.makedirs('logs', exist_ok=True)

# --- Logging setup ---
file_handler = logging.FileHandler('logs/app.log')
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [%(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

unauth_logger = logging.getLogger('unauthorized_access')
unauth_handler = logging.FileHandler(UNAUTHORIZED_LOG_PATH)
unauth_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
unauth_logger.addHandler(unauth_handler)
unauth_logger.setLevel(logging.INFO)

user_login_logger = logging.getLogger('user_login')
user_login_handler = logging.FileHandler(USER_LOGIN_LOG_PATH)
user_login_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
user_login_logger.addHandler(user_login_handler)
user_login_logger.setLevel(logging.INFO)


# --- User helper functions ---
def is_write_user(eppn):
    if os.path.exists(AUTHORIZED_USERS_FILE):
        with open(AUTHORIZED_USERS_FILE, 'r') as f:
            return eppn in [line.strip() for line in f]
    return False

def is_read_only_user(eppn):
    if os.path.exists(READONLY_USERS_FILE):
        with open(READONLY_USERS_FILE, 'r') as f:
            return eppn in [line.strip() for line in f]
    return False


# --- Database initialization ---
def init_db():
    newly_created = False
    if not os.path.exists(DB_FILE):
        app.logger.info("Initializing new database.")
        newly_created = True
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    query TEXT,
                    response TEXT,
                    is_independent_question TEXT DEFAULT '',
                    response_review TEXT DEFAULT '',
                    query_review TEXT DEFAULT '',
                    urls_review TEXT DEFAULT '',
                    tags TEXT DEFAULT '',
                    ai_generated_tags TEXT DEFAULT '',
                    last_updated_by TEXT DEFAULT NULL,
                    last_updated_at TEXT DEFAULT NULL
                )
            ''')
            conn.commit()
    else:
        app.logger.info("Database already exists.")

    if newly_created:
        logs = read_logs_from_files()
        with sqlite3.connect(DB_FILE) as conn:
            for log in logs:
                insert_log(conn, log)


def read_logs_from_files():
    log_entries = []
    start_date = datetime.min
    end_date = datetime.now()
    app.logger.info(f"Scanning log directory: {LOG_DIR}")

    for filename in sorted(os.listdir(LOG_DIR), reverse=True):
        filepath = os.path.join(LOG_DIR, filename)
        if not (filename.startswith('simple_qa.log') and (filename.endswith('.log') or filename.endswith('.gz'))):
            app.logger.info(f"Skipping file: {filename}")
            continue
        app.logger.info(f"Reading log file: {filepath}")
        try:
            if filename.endswith('.gz'):
                with gzip.open(filepath, 'rt') as f:
                    log_entries.extend(parse_log(f, start_date, end_date))
            else:
                with open(filepath, 'r') as f:
                    log_entries.extend(parse_log(f, start_date, end_date))
        except Exception as e:
            app.logger.error(f"Error processing file {filepath}: {e}")

    try:
        log_entries = sorted(
            log_entries,
            key=lambda x: datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S,%f'),
            reverse=True
        )
    except Exception as e:
        app.logger.error(f"Error sorting log entries: {e}")

    app.logger.info(f"Total log entries found: {len(log_entries)}")
    return log_entries


# --- Log parsing ---
def parse_log(file, start_date, end_date):
    pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - QUERY: (.*?)\nRESPONSE: (.*?)(?=\n\d{4}-\d{2}-\d{2}|\Z)',
        re.DOTALL
    )
    content = file.read()
    matches = pattern.finditer(content)
    entries = []
    for match in matches:
        ts_str = match.group(1)
        try:
            ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S,%f')
        except ValueError:
            continue
        if start_date <= ts <= end_date:
            response = match.group(3).strip()
            # Remove any trailing lines consisting solely of '#' characters.
            response = re.sub(r'\n#+\s*$', '', response)
            entries.append({
                'timestamp': ts_str,
                'query': match.group(2).strip(),
                'response': response,
                'is_independent_question': '',
                'response_review': '',
                'query_review': '',
                'urls_review': '',
                'tags': ''
            })
    app.logger.info(f"Parsed {len(entries)} entries from file.")
    return entries


def insert_log(conn, log):
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM logs WHERE timestamp=? AND query=?", (log['timestamp'], log['query']))
    if c.fetchone()[0] == 0:
        c.execute('''
            INSERT INTO logs (
                timestamp, query, response,
                is_independent_question, response_review,
                query_review, urls_review, tags, ai_generated_tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '')
        ''', (
            log['timestamp'],
            log['query'],
            log['response'],
            log['is_independent_question'],
            log['response_review'],
            log['query_review'],
            log['urls_review'],
            log['tags']
        ))
        conn.commit()
        app.logger.info(f"Inserted log with timestamp: {log['timestamp']}")
    else:
        app.logger.info(f"Log already exists for timestamp: {log['timestamp']}")

def read_tags():
    """
    Read tags.txt, ignore blank lines and lines starting with '#',
    and return a de-duplicated, order-preserving list of tags.
    """
    if os.path.exists(TAGS_FILE):
        seen = set()
        tags = []
        with open(TAGS_FILE, 'r') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line not in seen:
                    seen.add(line)
                    tags.append(line)
        return tags
    return []

# --- Graph generation ---
def generate_graph(metrics):
    dates = list(metrics.keys())
    vals = list(metrics.values())
    fig = go.Figure(data=go.Scatter(x=dates, y=vals, mode='lines+markers', name='Queries'))
    fig.update_layout(
        title='Number of Queries',
        xaxis_title='Date',
        yaxis_title='Count',
        template='plotly_white',
        height=400,
        margin=dict(l=40, r=40, t=40, b=40)
    )
    return pio.to_html(fig, full_html=False)


def get_week_range(year, week_num):
    start_of_year = datetime(year, 1, 1)
    start_of_week = start_of_year + timedelta(weeks=week_num - 1)
    start_of_week -= timedelta(days=start_of_week.weekday())
    end_of_week = start_of_week + timedelta(days=6)
    return start_of_week.strftime('%Y-%m-%d'), end_of_week.strftime('%Y-%m-%d')


def calculate_metrics(logs, view_by):
    metrics = defaultdict(int)
    for log in logs:
        dt_str = log['timestamp'].split(' ')[0]
        dt = datetime.strptime(dt_str, '%Y-%m-%d')
        if view_by == 'daily':
            key = dt.strftime('%Y-%m-%d')
        elif view_by == 'weekly':
            y, w = dt.isocalendar()[:2]
            start, end = get_week_range(y, w)
            key = f"{start} - {end}"
        else:  # monthly
            key = dt.strftime('%Y-%m')
        metrics[key] += 1

    if view_by == 'weekly':
        sorted_metrics = dict(sorted(
            metrics.items(),
            key=lambda x: datetime.strptime(x[0].split(' - ')[0], '%Y-%m-%d')
        ))
    else:
        sorted_metrics = dict(sorted(metrics.items(), key=lambda x: x[0]))
    return sorted_metrics


def is_reviewed(log):
    return any([
        log.get('is_independent_question'),
        log.get('response_review'),
        log.get('query_review'),
        log.get('urls_review'),
        log.get('tags'),
        log.get('last_updated_at')
    ])


def calculate_review_counts(logs):
    total = len(logs)
    reviewed_logs = [l for l in logs if is_reviewed(l)]
    not_reviewed_logs = [l for l in logs if not is_reviewed(l)]
    indep_yes = sum(1 for l in reviewed_logs if l['is_independent_question'] == "Yes")
    indep_no = sum(1 for l in reviewed_logs if l['is_independent_question'] == "No")

    def cnt(field, val):
        return sum(1 for l in reviewed_logs if l.get(field) == val)

    return {
        "total": total,
        "reviewed": len(reviewed_logs),
        "not_reviewed": len(not_reviewed_logs),
        "indep_yes": indep_yes,
        "indep_no": indep_no,
        "resp_correct": cnt("response_review", "Correct"),
        "resp_partially": cnt("response_review", "Partially"),
        "resp_incorrect": cnt("response_review", "Incorrect"),
        "resp_idk": cnt("response_review", "I Don't Know"),
        "query_good": cnt("query_review", "Good"),
        "query_acceptable": cnt("query_review", "Acceptable"),
        "query_bad": cnt("query_review", "Bad"),
        "query_idk": cnt("query_review", "I Don't Know"),
        "urls_good": cnt("urls_review", "Good"),
        "urls_acceptable": cnt("urls_review", "Acceptable"),
        "urls_bad": cnt("urls_review", "Bad"),
        "urls_idk": cnt("urls_review", "I Don't Know")
    }


def get_paginated_logs(logs, page, per_page):
    start = (page - 1) * per_page
    return logs[start:start + per_page]


# --- Routes ---
@app.route('/', methods=['GET'])
def home_route():
    if 'user' not in session:
        flash('You must be logged in.', 'danger')
        return redirect(url_for('login'))

    today = datetime.now().strftime('%Y-%m-%d')
    start_date = request.args.get('start_date', today)
    end_date = request.args.get('end_date', today)
    view_by = request.args.get('view_by', 'daily')
    page = int(request.args.get('page', 1))

    # existing filters
    selected_independent = request.args.get('independent', 'All')
    selected_response_review = request.args.getlist('response_review')
    selected_query_review = request.args.getlist('query_review')
    selected_urls_review = request.args.getlist('urls_review')
    selected_tags = request.args.getlist('tags')
    selected_review_status = request.args.get('review_status', 'All')
    # new has_tags filter
    selected_has_tags = request.args.get('has_tags', 'All')

    init_db()

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ?"
        params = [f"{start_date} 00:00:00,000", f"{end_date} 23:59:59,999"]

        if selected_independent != "All":
            sql += " AND is_independent_question=?"
            params.append(selected_independent)
        if selected_response_review:
            sql += " AND response_review IN ({})".format(','.join('?' for _ in selected_response_review))
            params.extend(selected_response_review)
        if selected_query_review:
            sql += " AND query_review IN ({})".format(','.join('?' for _ in selected_query_review))
            params.extend(selected_query_review)
        if selected_urls_review:
            sql += " AND urls_review IN ({})".format(','.join('?' for _ in selected_urls_review))
            params.extend(selected_urls_review)
        if selected_review_status == "Reviewed":
            sql += " AND (" + " OR ".join([
                "is_independent_question<>''",
                "response_review<>''",
                "query_review<>''",
                "urls_review<>''",
                "tags<>''",
                "last_updated_at IS NOT NULL"
            ]) + ")"
        elif selected_review_status == "Not Reviewed":
            sql += " AND (" + " AND ".join([
                "is_independent_question='' ",
                "response_review='' ",
                "query_review='' ",
                "urls_review='' ",
                "tags='' ",
                "last_updated_at IS NULL"
            ]) + ")"
        if selected_tags:
            sql += " AND ("
            for idx, tag in enumerate(selected_tags):
                sql += "(tags LIKE ? OR ai_generated_tags LIKE ?)"
                params.extend([f'%{tag}%', f'%{tag}%'])
                if idx < len(selected_tags) - 1:
                    sql += " OR "
            sql += ")"

        # apply has_tags filter
        if selected_has_tags == "Has":
            sql += " AND (tags<>'' OR ai_generated_tags<>'')"
        elif selected_has_tags == "None":
            sql += " AND tags='' AND ai_generated_tags=''"

        sql += " ORDER BY timestamp DESC"
        c.execute(sql, params)
        all_entries = [dict(r) for r in c.fetchall()]

    total_logs = len(all_entries)
    paginated_logs = get_paginated_logs(all_entries, page, PER_PAGE)
    total_pages = (total_logs + PER_PAGE - 1) // PER_PAGE
    next_page = page + 1 if page < total_pages else None
    prev_page = page - 1 if page > 1 else None

    # Sanitize & clean
    for log in paginated_logs:
        if not log.get('query', '').strip():
            log['query'] = "(No Query Provided)"
        else:
            log['query'] = escape(log['query'])
        if log.get('response'):
            log['response'] = bleach.clean(
                log['response'],
                tags=ALLOWED_TAGS,
                attributes=ALLOWED_ATTRIBUTES,
                strip=True
            )
        else:
            log['response'] = "(No Response Provided)"

    mets = calculate_metrics(all_entries, view_by)
    rc = calculate_review_counts(all_entries)

    # Percentage helpers
    def pct(x, base): return round(x / base * 100, 1) if base > 0 else 0

    total = rc["total"]
    reviewed = rc["reviewed"]
    not_rev = rc["not_reviewed"]
    p_rev = pct(reviewed, total)
    p_not_rev = pct(not_rev, total)

    indep_yes = rc["indep_yes"]
    indep_no = rc["indep_no"]
    yn_sum = indep_yes + indep_no
    yes_pct = pct(indep_yes, yn_sum)
    no_pct = pct(indep_no, yn_sum)

    r_corr = rc["resp_correct"]
    r_part = rc["resp_partially"]
    r_inc = rc["resp_incorrect"]
    r_idk = rc["resp_idk"]
    sum_resp = r_corr + r_part + r_inc + r_idk

    q_good = rc["query_good"]
    q_acc = rc["query_acceptable"]
    q_bad = rc["query_bad"]
    q_idk = rc["query_idk"]
    sum_q = q_good + q_acc + q_bad + q_idk

    u_good = rc["urls_good"]
    u_acc = rc["urls_acceptable"]
    u_bad = rc["urls_bad"]
    u_idk = rc["urls_idk"]
    sum_u = u_good + u_acc + u_bad + u_idk

    metrics_summary = {
        'overall': f"Total Queries: {total} (100%), Reviewed: {reviewed} ({p_rev}%), Not Reviewed: {not_rev} ({p_not_rev}%)",
        'independent': f"Is this an independent question for the QA tool? Yes: {indep_yes} ({yes_pct}%), No: {indep_no} ({no_pct}%)",
        'response': (
            f"Response Review (Reviewed + Independent=Yes): "
            f"Correct: {r_corr} ({pct(r_corr,sum_resp)}%), "
            f"Partially: {r_part} ({pct(r_part,sum_resp)}%), "
            f"Incorrect: {r_inc} ({pct(r_inc,sum_resp)}%), "
            f"I Don't Know: {r_idk} ({pct(r_idk,sum_resp)}%)"
        ),
        'query': (
            f"Query Review (Reviewed + Independent=Yes): "
            f"Good: {q_good} ({pct(q_good,sum_q)}%), "
            f"Acceptable: {q_acc} ({pct(q_acc,sum_q)}%), "
            f"Bad: {q_bad} ({pct(q_bad,sum_q)}%), "
            f"I Don't Know: {q_idk} ({pct(q_idk,sum_q)}%)"
        ),
        'urls': (
            f"URLs in Response Review (Reviewed + Independent=Yes): "
            f"Good: {u_good} ({pct(u_good,sum_u)}%), "
            f"Acceptable: {u_acc} ({pct(u_acc,sum_u)}%), "
            f"Bad: {u_bad} ({pct(u_bad,sum_u)}%), "
            f"I Don't Know: {u_idk} ({pct(u_idk,sum_u)}%)"
        )
    }

    def param_escape(v): return v.replace('&','%26').replace('=','%3D').replace(' ','+')
    param_str = (
        f"&start_date={param_escape(start_date)}"
        f"&end_date={param_escape(end_date)}"
        f"&view_by={param_escape(view_by)}"
        f"&independent={param_escape(selected_independent)}"
        f"&review_status={param_escape(selected_review_status)}"
    )
    for rr in selected_response_review:
        param_str += f"&response_review={param_escape(rr)}"
    for qr in selected_query_review:
        param_str += f"&query_review={param_escape(qr)}"
    for ur in selected_urls_review:
        param_str += f"&urls_review={param_escape(ur)}"
    for t in selected_tags:
        param_str += f"&tags={param_escape(t)}"
    # include has_tags in param_str
    param_str += f"&has_tags={param_escape(selected_has_tags)}"

    return render_template(
        'index.html',
        logs=paginated_logs,
        total_logs=total_logs,
        available_tags=read_tags(),
        graph_html=generate_graph(mets),
        metrics_text=[f"{k}: {v} queries" for k, v in mets.items()],
        metrics_summary=metrics_summary,
        filter_summary_message=Markup(f"<h3>Total Queries in Selected Range</h3>"),
        start_date=start_date,
        end_date=end_date,
        view_by=view_by,
        selected_independent=selected_independent,
        selected_response_review=selected_response_review,
        selected_query_review=selected_query_review,
        selected_urls_review=selected_urls_review,
        selected_tags=selected_tags,
        selected_review_status=selected_review_status,
        # new has_tags parameters
        selected_has_tags=selected_has_tags,
        has_tags_options=["All", "Has", "None"],

        review_status_options=["All", "Reviewed", "Not Reviewed"],
        is_independent_options=["All", "Yes", "No"],
        response_review_options=["Correct", "Partially", "Incorrect", "I Don't Know"],
        query_review_options=["Good", "Acceptable", "Bad", "I Don't Know"],
        urls_review_options=["Good", "Acceptable", "Bad", "I Don't Know"],
        page=page,
        total_pages=total_pages,
        next_page=next_page,
        prev_page=prev_page,
        param_str=param_str,
        read_only=session.get('read_only', False)
    )


@app.route('/update_entry', methods=['POST'])
def update_entry():
    # Block write actions for read-only users.
    if session.get('read_only'):
        return jsonify({'status': 'error', 'message': 'Read-only users cannot update entries.'}), 403

    try:
        data = request.json
        log_id = data['id']

        # 1) Fetch the old values
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT is_independent_question AS independent,
                       response_review        AS response,
                       query_review           AS query,
                       urls_review            AS urls,
                       tags
                  FROM logs
                 WHERE id=?
            """, (log_id,))
            old = dict(cur.fetchone())

        # 2) Build the new values (with your defaulting logic)
        new = {
            'independent': data.get('is_independent_question', ''),
            'response':    data.get('response_review',       ''),
            'query':       data.get('query_review',          ''),
            'urls':        data.get('urls_review',           ''),
            'tags':        ','.join(data.get('tags', []))
        }

        if new['independent'] == 'No':
            new.update({'response':'', 'query':'', 'urls':'', 'tags':''})
        else:
            new['independent'] = 'Yes'
            if not new['response']: new['response'] = 'Correct'
            if not new['query']:    new['query']    = 'Good'
            if not new['urls']:     new['urls']     = 'Good'

        reviewer = session['user']['eppn']
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 3) Update the DB
        with sqlite3.connect(DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE logs
                   SET is_independent_question=?,
                       response_review=?,
                       query_review=?,
                       urls_review=?,
                       tags=?,
                       last_updated_by=?,
                       last_updated_at=?
                 WHERE id=?
            """, (
                new['independent'],
                new['response'],
                new['query'],
                new['urls'],
                new['tags'],
                reviewer,
                ts,
                log_id
            ))
            conn.commit()

        # 4) Build a simple list of changed fields
        changed = [k for k in old if old[k] != new[k]]
        msg = f"Record {log_id} updated: fields changed = {', '.join(changed) or 'none'}"

        # 5) Log to both console and file
        print(msg)                   # console
        app.logger.info(msg)         # app.log

        return jsonify({
            'status': 'success',
            'last_updated_by': reviewer,
            'last_updated_at': ts
        })

    except Exception as e:
        err = f"Error updating record {data.get('id')}: {e}"
        print(err)
        app.logger.error(err, exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/get_metrics', methods=['GET'])
def get_metrics_endpoint():
    # same filtering logic as home_route, including has_tags...
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    view_by = request.args.get('view_by', 'daily')
    independent = request.args.get('independent', 'All')
    response_reviews = request.args.getlist('response_review')
    query_reviews = request.args.getlist('query_review')
    urls_reviews = request.args.getlist('urls_review')
    tags = request.args.getlist('tags')
    review_status = request.args.get('review_status', 'All')
    has_tags = request.args.get('has_tags', 'All')

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ?"
        params = [f"{start_date} 00:00:00,000", f"{end_date} 23:59:59,999"]

        # apply all filters...
        if independent != "All":
            sql += " AND is_independent_question=?"
            params.append(independent)
        if response_reviews:
            sql += " AND response_review IN ({})".format(','.join('?' for _ in response_reviews))
            params.extend(response_reviews)
        if query_reviews:
            sql += " AND query_review IN ({})".format(','.join('?' for _ in query_reviews))
            params.extend(query_reviews)
        if urls_reviews:
            sql += " AND urls_review IN ({})".format(','.join('?' for _ in urls_reviews))
            params.extend(urls_reviews)
        if review_status == "Reviewed":
            sql += " AND (" + " OR ".join([
                "is_independent_question<>''",
                "response_review<>''",
                "query_review<>''",
                "urls_review<>''",
                "tags<>''",
                "last_updated_at IS NOT NULL"
            ]) + ")"
        elif review_status == "Not Reviewed":
            sql += " AND (" + " AND ".join([
                "is_independent_question='' ",
                "response_review='' ",
                "query_review='' ",
                "urls_review='' ",
                "tags='' ",
                "last_updated_at IS NULL"
            ]) + ")"
        if tags:
            sql += " AND ("
            for idx, tag in enumerate(tags):
                sql += "(tags LIKE ? OR ai_generated_tags LIKE ?)"
                params.extend([f'%{tag}%', f'%{tag}%'])
                if idx < len(tags) - 1:
                    sql += " OR "
            sql += ")"
        # has_tags filter
        if has_tags == "Has":
            sql += " AND (tags<>'' OR ai_generated_tags<>'')"
        elif has_tags == "None":
            sql += " AND tags='' AND ai_generated_tags=''"

        sql += " ORDER BY timestamp DESC"
        c.execute(sql, params)
        rows = [dict(r) for r in c.fetchall()]

    mets = calculate_metrics(rows, view_by)
    rc = calculate_review_counts(rows)

    def pct(x, base): return round(x / base * 100, 1) if base > 0 else 0

    total = rc["total"]
    reviewed = rc["reviewed"]
    not_rev = rc["not_reviewed"]
    p_rev = pct(reviewed, total)
    p_not_rev = pct(not_rev, total)

    indep_yes = rc["indep_yes"]
    indep_no = rc["indep_no"]
    yn_sum = indep_yes + indep_no
    yes_pct = pct(indep_yes, yn_sum)
    no_pct = pct(indep_no, yn_sum)

    r_corr = rc["resp_correct"]
    r_part = rc["resp_partially"]
    r_inc = rc["resp_incorrect"]
    r_idk = rc["resp_idk"]
    sum_resp = r_corr + r_part + r_inc + r_idk

    q_good = rc["query_good"]
    q_acc = rc["query_acceptable"]
    q_bad = rc["query_bad"]
    q_idk = rc["query_idk"]
    sum_q = q_good + q_acc + q_bad + q_idk

    u_good = rc["urls_good"]
    u_acc = rc["urls_acceptable"]
    u_bad = rc["urls_bad"]
    u_idk = rc["urls_idk"]
    sum_u = u_good + u_acc + u_bad + u_idk

    metrics_summary = {
        'overall': f"Total Queries: {total} (100%), Reviewed: {reviewed} ({p_rev}%), Not Reviewed: {not_rev} ({p_not_rev}%)",
        'independent': f"Independent? Yes: {indep_yes} ({yes_pct}%), No: {indep_no} ({no_pct}%)",
        'response': (
            f"Response Review: Correct {r_corr} ({pct(r_corr,sum_resp)}%), "
            f"Partially {r_part} ({pct(r_part,sum_resp)}%), "
            f"Incorrect {r_inc} ({pct(r_inc,sum_resp)}%), "
            f"I Don't Know {r_idk} ({pct(r_idk,sum_resp)}%)"
        ),
        'query': (
            f"Query Review: Good {q_good} ({pct(q_good,sum_q)}%), "
            f"Acceptable {q_acc} ({pct(q_acc,sum_q)}%), "
            f"Bad {q_bad} ({pct(q_bad,sum_q)}%), "
            f"I Don't Know {q_idk} ({pct(q_idk,sum_q)}%)"
        ),
        'urls': (
            f"URLs Review: Good {u_good} ({pct(u_good,sum_u)}%), "
            f"Acceptable {u_acc} ({pct(u_acc,sum_u)}%), "
            f"Bad {u_bad} ({pct(u_bad,sum_u)}%), "
            f"I Don't Know {u_idk} ({pct(u_idk,sum_u)}%)"
        )
    }

    return jsonify({'metrics_summary': metrics_summary})


@app.route('/download_all', methods=['GET'])
def download_all():
    # --- Gather params ---
    file_type        = request.args.get('file_type', 'csv').lower()
    start_date       = request.args.get('start_date')
    end_date         = request.args.get('end_date')
    independent      = request.args.get('independent', 'All')
    response_reviews = request.args.getlist('response_review')
    query_reviews    = request.args.getlist('query_review')
    urls_reviews     = request.args.getlist('urls_review')
    selected_tags    = request.args.getlist('tags')
    review_status    = request.args.get('review_status', 'All')
    has_tags         = request.args.get('has_tags', 'All')

    # --- Build & run query ---
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ?"
        params = [f"{start_date} 00:00:00,000", f"{end_date} 23:59:59,999"]

        if independent != "All":
            sql += " AND is_independent_question=?"
            params.append(independent)
        if response_reviews:
            sql += " AND response_review IN ({})".format(",".join("?"*len(response_reviews)))
            params.extend(response_reviews)
        if query_reviews:
            sql += " AND query_review IN ({})".format(",".join("?"*len(query_reviews)))
            params.extend(query_reviews)
        if urls_reviews:
            sql += " AND urls_review IN ({})".format(",".join("?"*len(urls_reviews)))
            params.extend(urls_reviews)

        # Reviewed / Not Reviewed
        if review_status == "Reviewed":
            sql += " AND (" + " OR ".join([
                "is_independent_question<>''",
                "response_review<>''",
                "query_review<>''",
                "urls_review<>''",
                "tags<>''",
                "last_updated_at IS NOT NULL"
            ]) + ")"
        elif review_status == "Not Reviewed":
            sql += " AND (" + " AND ".join([
                "is_independent_question='' ",
                "response_review='' ",
                "query_review='' ",
                "urls_review='' ",
                "tags='' ",
                "last_updated_at IS NULL"
            ]) + ")"

        # Has Tags filter
        if has_tags == "Has Tags":
            sql += " AND (tags<>'' OR ai_generated_tags<>'')"
        elif has_tags == "No Tags":
            sql += " AND tags='' AND ai_generated_tags=''"

        # Specific tag values
        if selected_tags:
            sql += " AND (" + " OR ".join("(tags LIKE ? OR ai_generated_tags LIKE ?)"
                                           for _ in selected_tags) + ")"
            for t in selected_tags:
                params.extend([f"%{t}%", f"%{t}%"])

        sql += " ORDER BY timestamp DESC"
        c.execute(sql, params)
        rows = [dict(r) for r in c.fetchall()]

    # --- Export ---
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    # CSV
    if file_type == 'csv':
        def generate_csv():
            buf = StringIO()
            writer = csv.writer(buf)
            writer.writerow([
                'Timestamp','Query','Response',
                'Independent?','Response Review','Query Review','URLs Review',
                'Tags','AI Generated Tags','Last Updated By','Last Updated At'
            ])
            yield buf.getvalue()
            for log in rows:
                buf.seek(0); buf.truncate(0)
                writer.writerow([
                    log['timestamp'],
                    log['query'],
                    log['response'],
                    log['is_independent_question'],
                    log['response_review'],
                    log['query_review'],
                    log['urls_review'],
                    log['tags'],
                    log.get('ai_generated_tags',''),
                    log.get('last_updated_by',''),
                    log.get('last_updated_at',''),
                ])
                yield buf.getvalue()

        return Response(
            generate_csv(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=logs_{timestamp_str}.csv'}
        )

    # XLS / XLSX
    elif file_type in ('xls', 'xlsx'):
        buf = BytesIO()
        df = pd.DataFrame(rows)
        # ensure columns order
        df = df[[
            'timestamp','query','response',
            'is_independent_question','response_review','query_review','urls_review',
            'tags','ai_generated_tags','last_updated_by','last_updated_at'
        ]]
        with pd.ExcelWriter(buf, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Logs')
        buf.seek(0)
        return send_file(
            buf,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'logs_{timestamp_str}.xlsx'
        )

    else:
        return "Invalid file type", 400

@app.route('/login')
def login():
    redirect_uri = 'https://access-ai.ccs.uky.edu:2222/authorize'
    nonce = os.urandom(16).hex()
    session['nonce'] = nonce
    idp_hint = 'https://access-ci.org/idp'
    app.logger.info(f"Redirect URI: {redirect_uri}")
    return oauth.cilogon.authorize_redirect(redirect_uri, nonce=nonce, idphint=idp_hint)

@app.route('/authorize')
def authorize():
    try:
        token = oauth.cilogon.authorize_access_token()
        nonce = session.pop('nonce', None)
        user = oauth.cilogon.parse_id_token(token, nonce=nonce)
        user_info = oauth.cilogon.userinfo()
        user['eppn'] = user_info.get('ePPN') or user_info.get('sub')
        session['user'] = user

        # if not in either list, kick them out
        if not (is_write_user(user['eppn']) or is_read_only_user(user['eppn'])):
            ipaddr = request.headers.get('X-Forwarded-For', request.remote_addr)
            unauth_logger.info(f"Unauthorized user {user['eppn']} from {ipaddr}")
            flash('You are not authorized.', 'danger')
            session.clear()
            return redirect(url_for('unauthorized'))

        # otherwise set read_only flag and continue
        session['read_only'] = is_read_only_user(user['eppn'])
        user_login_logger.info(f"User {user['eppn']} logged in. Read-only: {session['read_only']}")
        flash('Authorization successful!', 'success')

    except Exception as e:
        # if anything went wrong in the try block, log & bounce back home
        flash(f'Authorization failed: {e}', 'danger')
        return redirect('/')   # <-- either redirect('/') or url_for('home_route')

    # on success, send them to the real home page
    return redirect('/')

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=2220)
