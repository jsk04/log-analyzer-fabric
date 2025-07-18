# app.py

import os
import sqlite3
import logging
import re
import json
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
import plotly.utils
import plotly.express as px
import bleach
from io import StringIO, BytesIO
import markdown

load_dotenv()

# --- Configuration ---
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')

LOG_DIR = os.getenv('LOG_DIR')
DB_FILE = os.getenv('DATABASE_PATH')

AUTHORIZED_USERS_FILE = os.getenv('AUTHORIZED_USERS_FILE')
READONLY_USERS_FILE = os.getenv('READONLY_USERS_FILE')

UNAUTHORIZED_LOG_PATH = 'logs/unauthorized_access.log'
USER_LOGIN_LOG_PATH = 'logs/user_logins.log'

FILES_OFFSETS_PATH = os.getenv('FILES_OFFSETS_PATH')
PER_PAGE = 10

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
                    tool TEXT,
                    model TEXT,
                    tester TEXT,
                    is_independent_question TEXT DEFAULT '',
                    response_review TEXT DEFAULT '',
                    query_review TEXT DEFAULT '',
                    urls_review TEXT DEFAULT '',
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

def load_offsets():
    if os.path.exists(FILES_OFFSETS_PATH):
        with open(FILES_OFFSETS_PATH, 'r') as f:
            return json.load(f)
    return {}

# Save current file positions
def save_offsets(positions):
    with open(FILES_OFFSETS_PATH, 'w') as f:
        json.dump(positions, f)

def read_logs_from_files():
    log_entries = []
    start_date = datetime.min
    end_date = datetime.now()
    app.logger.info(f"Scanning log directory: {LOG_DIR}")

    # Get the file positions info
    file_positions = load_offsets()
    
    for filename in sorted(os.listdir(LOG_DIR), reverse=True):
        filepath = os.path.join(LOG_DIR, filename)
        if not filename.endswith('_custom.log'):
            app.logger.info(f"Skipping file: {filename}")
            continue

        # Get the last read position of the file 
        # If it hasn't been read before, set it to 0
        last_pos = file_positions.get(filename, 0)
        app.logger.info(f"Reading log file: {filepath}")
        try:
            with open(filepath, 'r') as f:
                # Only read from last read position 
                f.seek(last_pos)
                new_content = f.read()
                log_entries.extend(parse_log(new_content, start_date, end_date))
                file_positions[filename] = f.tell()
        except Exception as e:
            app.logger.error(f"Error processing file {filepath}: {e}")
    
    # Save file offsets
    save_offsets(file_positions)

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
def parse_log(content, start_date, end_date):

    pattern = re.compile(
            r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - QUERY: (.*?)\nRESPONSE:\s+(.*?)(?:\n+|\s+)MODEL:\s+(.*?)\nTOOL: (.*?)\nTESTER: (.*?)(?=\n\d{4}-\d{2}-\d{2}|\Z)',
                    re.DOTALL | re.MULTILINE
            )
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
                'tool': match.group(5).strip(),
                'model': match.group(4).strip(),
                'tester': match.group(6).strip(),
                'is_independent_question': '',
                'response_review': '',
                'query_review': '',
                'urls_review': ''
            })
    return entries

def insert_log(conn, log):
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM logs WHERE timestamp=? AND query=?", (log['timestamp'], log['query']))
    if c.fetchone()[0] == 0:
        c.execute('''
            INSERT INTO logs (
                timestamp, query, response, tool, model, tester,
                is_independent_question, response_review,
                query_review, urls_review
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log['timestamp'],
            log['query'],
            log['response'],
            log['tool'],
            log['model'],
            log['tester'],
            log['is_independent_question'],
            log['response_review'],
            log['query_review'],
            log['urls_review']
        ))
        conn.commit()
        app.logger.info(f"Inserted log with timestamp: {log['timestamp']}")
    else:
        app.logger.info(f"Log already exists for timestamp: {log['timestamp']}")

# ------------------------------------- Function to build models graph --------------------------------
def generate_graph(logs):
    metrics = calculate_model_metrics(logs)

    # identify the stack that we want separated visually
    highlight_group = 'Not Reviewed'
    spacer_value1 = 0.05
    spacer_value2 = 0.1

    # print(f"This is the model_metrics dictionary: {metrics}")
    # Take dictionary and turn it into flat data
    flat_metrics = []
    for model, model_metrics in metrics.items():
        correct = model_metrics.get('Correct', 0)
        partial = model_metrics.get('Partially Correct', 0)
        incorrect = model_metrics.get('Incorrect', 0)
        idk = model_metrics.get("I don't know", 0)
        not_reviewed = model_metrics.get('Not Reviewed', 0)

        base_sum = correct + partial + incorrect + idk 
        total_sum = base_sum + not_reviewed
        
        nr_nonzero = False 
        correct_nonzero = False
        partial_nonzero = False
        incorrect_nonzero = False 
        idk_nonzero = False 
        # print(f"This is the metrics dictionary for this {model}:\n{model_metrics}")
        for metric, val in model_metrics.items():
            if metric != 'Not Reviewed':
                percent = pct(val, base_sum)

            if metric == 'Not Reviewed':
                percent = pct(val, total_sum)
                if val > 0:
                    nr_nonzero = True
            flat_metrics.append({
                'Model': model, 'Metric': metric, 'Value': val,
                'Percent': f'{percent:.1f}%', 'CustomHover': f'{metric}<br>{percent:.1f}'
            })
            
            # Keep track of metrics with values of 0
            if metric == "Correct" and val > 0:
                correct_nonzero = True
            if metric == "Partially Correct" and val > 0:
                partial_nonzero = True
            if metric == "Incorrect" and val > 0:
                incorrect_nonzero = True 
            if metric == "I don't know" and val > 0:
                idk_nonzero = True

        # Assign spacer values based on whether metrics are nonzero
        if correct_nonzero and partial_nonzero:
            spacer_value1 = 0.01
        else:
            spacer_value1 = 0

        if correct_nonzero or partial_nonzero or incorrect_nonzero or idk_nonzero: 
            spacer_value2 = 0.05
        else:
            spacer_value2 = 0
        
        # Add spacer into flat_metrics
        flat_metrics.append({
                    'Model': model, 'Metric': 'Spacer1', 'Value': spacer_value1,
                    'Percent': '', 'CustomHover': ''
                })
        flat_metrics.append({
                    'Model': model, 'Metric': 'Spacer2', 'Value': spacer_value2,
                    'Percent': '', 'CustomHover': ''
                })

    # Convert into a data frame
    if not flat_metrics:
        df = pd.DataFrame(columns=['Model', 'Metric', 'Value', 'Percent', 'CustomHover'])
    else: 
        df = pd.DataFrame(flat_metrics)

    # Custom color map
    color_map = {
        'Correct': 'rgba(31,255,0,0.4)',
        'Incorrect': 'rgba(255, 99, 71, 0.8)',
        'Partially Correct': 'rgba(31,255,0,0.4)',
        "I don't know": 'rgba(255,255,0,0.7)',
        "Not Reviewed": 'rgba(180, 180, 180, 1)',
        "Spacer1": 'rgba(0,0,0,0)',
        "Spacer2": 'rgba(0,0,0,0)'
    }
    category_order = ['Correct', 'Spacer1', 'Partially Correct', 'Incorrect', "I don't know", "Spacer2", "Not Reviewed"]

    # Step 4: Build the plot
    fig = px.bar(
        df,
        x='Model',
        y='Value',
        color='Metric',
        color_discrete_map=color_map,
        category_orders={'Metric': category_order},
        custom_data=['CustomHover'],
        barmode='stack'
    )

    # Step 5: Customize hover tooltips
    fig.update_traces(
        hovertemplate='%{customdata[0]}<extra></extra>' if not df.empty else '',
        selector=lambda trace: trace.name != 'Spacer1' or trace.name != 'Spacer2'
    )

    # Hide spacer from legend and tooltip
    fig.for_each_trace(lambda trace: trace.update(showlegend=False, hoverinfo='skip') if trace.name == 'Spacer1' or trace.name == 'Spacer2' else ())

    # Update layout with axis labels and template
    fig.update_layout(
        xaxis_title="Model",
        yaxis_title="Number of Queries",
        title="Accuracy of Responses by Model",
        template="plotly_white"
    )

    if df.empty:
        fig.add_annotation(
            text="No data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=16),
            align="center"
        )
    
    # return fig
    return pio.to_html(fig, full_html=False, include_plotlyjs='cdn')

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
        log.get('last_updated_at')
    ])

def cnt(reviewed_logs, field, val):
    return sum(1 for l in reviewed_logs if l.get(field) == val)


# Percentage helpers
def pct(x, base): return round(x / base * 100, 1) if base > 0 else 0

# -------------------------- Helper for building models graph ------------------------------
def calculate_model_metrics(logs):
    models = set()
    for log in logs:
        models.add(log['model'])
    
    # print(f"This is the set of models {models}")
    models_metrics = {model: {} for model in models}
    # models_metrics = defaultdict(dict)
    # models_metrics.keys = models
    for model in models_metrics.keys():
        model_logs = [l for l in logs if l['model'] == model]
        reviewed_logs = [l for l in model_logs if is_reviewed(l)]
        models_metrics[model] = {
            "Not Reviewed": len(model_logs) - len(reviewed_logs),
            "Correct": cnt(reviewed_logs, "response_review", "Correct"),
            "Partially Correct": cnt(reviewed_logs, "response_review", "Partially"),
            "Incorrect": cnt(reviewed_logs, "response_review", "Incorrect"),
            "I don't know": cnt(reviewed_logs, "response_review", "I Don't Know"),
        }
    return models_metrics

def calculate_review_counts(logs):
    total = len(logs)
    reviewed_logs = [l for l in logs if is_reviewed(l)]
    not_reviewed_logs = [l for l in logs if not is_reviewed(l)]
    indep_yes = sum(1 for l in reviewed_logs if l['is_independent_question'] == "Yes")
    indep_no = sum(1 for l in reviewed_logs if l['is_independent_question'] == "No")

    return {
        "total": total,
        "reviewed": len(reviewed_logs),
        "not_reviewed": len(not_reviewed_logs),
        "indep_yes": indep_yes,
        "indep_no": indep_no,
        "resp_correct": cnt(reviewed_logs, "response_review", "Correct"),
        "resp_partially": cnt(reviewed_logs, "response_review", "Partially"),
        "resp_incorrect": cnt(reviewed_logs, "response_review", "Incorrect"),
        "resp_idk": cnt(reviewed_logs, "response_review", "I Don't Know"),
        "query_good": cnt(reviewed_logs, "query_review", "Good"),
        "query_acceptable": cnt(reviewed_logs, "query_review", "Acceptable"),
        "query_bad": cnt(reviewed_logs, "query_review", "Bad"),
        "query_idk": cnt(reviewed_logs, "query_review", "I Don't Know"),
        "urls_good": cnt(reviewed_logs, "urls_review", "Good"),
        "urls_acceptable": cnt(reviewed_logs, "urls_review", "Acceptable"),
        "urls_bad": cnt(reviewed_logs, "urls_review", "Bad"),
        "urls_idk": cnt(reviewed_logs, "urls_review", "I Don't Know")
    }


def get_paginated_logs(logs, page, per_page):
    start = (page - 1) * per_page
    return logs[start:start + per_page]


# --- Routes ---
@app.route('/', methods=['GET'])
def home_route():
    # if 'user' not in session:
    #     flash('You must be logged in.', 'danger')
    #     return redirect(url_for('login'))

    today = datetime.now().strftime('%Y-%m-%d')
    start_date = request.args.get('start_date', today)
    end_date = request.args.get('end_date', today)
    view_by = request.args.get('view_by', 'daily')
    page = int(request.args.get('page', 1))

    # existing filters
    selected_tool = request.args.get('tool', 'All')
    selected_model = request.args.get('model', 'All')
    selected_independent = request.args.get('independent', 'All')
    selected_response_review = request.args.getlist('response_review')
    selected_query_review = request.args.getlist('query_review')
    selected_urls_review = request.args.getlist('urls_review')
    selected_review_status = request.args.get('review_status', 'All')

    init_db()

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ?"
        params = [f"{start_date} 00:00:00,000", f"{end_date} 23:59:59,999"]

        if selected_tool != 'All':
            sql += " AND tool=?"
            params.append(selected_tool)
        if selected_model != "All":
            sql += " AND model=?"
            params.append(selected_model)
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
                "last_updated_at IS NOT NULL"
            ]) + ")"
        elif selected_review_status == "Not Reviewed":
            sql += " AND (" + " AND ".join([
                "is_independent_question='' ",
                "response_review='' ",
                "query_review='' ",
                "urls_review='' ",
                "last_updated_at IS NULL"
            ]) + ")"

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
            log['response'] = markdown.markdown(log['response'])
        else:
            log['response'] = "(No Response Provided)"

    mets = calculate_metrics(all_entries, view_by)
    rc = calculate_review_counts(all_entries)

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
    
    # fig = generate_graph(all_entries)
    # graph_html = pio.to_html(fig,full_html=False,include_plotlyjs='cdn')
    return render_template(
        'index.html',
        logs=paginated_logs,
        total_logs=total_logs,
        graph_html=generate_graph(all_entries),
        metrics_text=[f"{k}: {v} queries" for k, v in mets.items()],
        metrics_summary=metrics_summary,
        filter_summary_message=Markup(f"<h3>Total Queries in Selected Range</h3>"),
        start_date=start_date,
        end_date=end_date,
        view_by=view_by,
        selected_tool=selected_tool,
        selected_model=selected_model,
        selected_independent=selected_independent,
        selected_response_review=selected_response_review,
        selected_query_review=selected_query_review,
        selected_urls_review=selected_urls_review,
        selected_review_status=selected_review_status,

        review_status_options=["All", "Reviewed", "Not Reviewed"],
        tool_options=["All", "Code Generation", "Q&A"],
        # Need to fill in model options
        model_options_map = {},
        model_options=["All", "codestral",
                     "codellama:latest",
                     "codellama:13b",
                     "codegemma:7b",
                     "phi4",
                     "mistral-small",
                     "deepseek-coder-v2",
                     "gpt-4o-mini"],
        # qa_options=[""],
        # cg_options=[""],
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
                       urls_review            AS urls
                  FROM logs
                 WHERE id=?
            """, (log_id,))
            old = dict(cur.fetchone())

        # 2) Build the new values (with your defaulting logic)
        new = {
            'independent': data.get('is_independent_question', ''),
            'response':    data.get('response_review',       ''),
            'query':       data.get('query_review',          ''),
            'urls':        data.get('urls_review',           '')
        }

        if new['independent'] == 'No':
            new.update({'response':'', 'query':'', 'urls':''})
        else:
            new['independent'] = 'Yes'
            if not new['response']: new['response'] = 'Correct'
            if not new['query']:    new['query']    = 'Good'
            if not new['urls']:     new['urls']     = 'Good'

        # reviewer = session['user']['eppn']
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
                       last_updated_at=?
                 WHERE id=?
            """, (
                new['independent'],
                new['response'],
                new['query'],
                new['urls'],
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
    tool = request.args.get('tool', 'All')
    model = request.args.get('model', 'All')
    independent = request.args.get('independent', 'All')
    response_reviews = request.args.getlist('response_review')
    query_reviews = request.args.getlist('query_review')
    urls_reviews = request.args.getlist('urls_review')
    review_status = request.args.get('review_status', 'All')

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ?"
        params = [f"{start_date} 00:00:00,000", f"{end_date} 23:59:59,999"]

        # apply all filters...
        if tool != 'All':
            sql += " AND tool=?"
            params.append(tool)
        if model != "All":
            sql += " AND model=?"
            params.append(model)
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
                "urls_review<>''"
                "last_updated_at IS NOT NULL"
            ]) + ")"
        elif review_status == "Not Reviewed":
            sql += " AND (" + " AND ".join([
                "is_independent_question='' ",
                "response_review='' ",
                "query_review='' ",
                "urls_review='' "
                "last_updated_at IS NULL"
            ]) + ")"
        
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

# @app.route('/update_graph', methods=['GET'])
# def update_graph():
#     # Get the latest logs
#     start_date = request.args.get('start_date')
#     end_date = request.args.get('end_date')
#     view_by = request.args.get('view_by', 'daily')
#     tool = request.args.get('tool', 'All')
#     model = request.args.get('model', 'All')
#     independent = request.args.get('independent', 'All')
#     response_reviews = request.args.getlist('response_review')
#     query_reviews = request.args.getlist('query_review')
#     urls_reviews = request.args.getlist('urls_review')
#     review_status = request.args.get('review_status', 'All')

#     with sqlite3.connect(DB_FILE) as conn:
#         conn.row_factory = sqlite3.Row
#         c = conn.cursor()
#         sql = "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ?"
#         params = [f"{start_date} 00:00:00,000", f"{end_date} 23:59:59,999"]

#         # apply all filters...
#         if tool != 'All':
#             sql += " AND tool=?",
#             params.append(tool)
#         if model != "All":
#             sql += " AND model=?"
#             params.append(model)
#         if independent != "All":
#             sql += " AND is_independent_question=?"
#             params.append(independent)
#         if response_reviews:
#             sql += " AND response_review IN ({})".format(','.join('?' for _ in response_reviews))
#             params.extend(response_reviews)
#         if query_reviews:
#             sql += " AND query_review IN ({})".format(','.join('?' for _ in query_reviews))
#             params.extend(query_reviews)
#         if urls_reviews:
#             sql += " AND urls_review IN ({})".format(','.join('?' for _ in urls_reviews))
#             params.extend(urls_reviews)
#         if review_status == "Reviewed":
#             sql += " AND (" + " OR ".join([
#                 "is_independent_question<>''",
#                 "response_review<>''",
#                 "query_review<>''",
#                 "urls_review<>''"
#                 "last_updated_at IS NOT NULL"
#             ]) + ")"
#         elif review_status == "Not Reviewed":
#             sql += " AND (" + " AND ".join([
#                 "is_independent_question='' ",
#                 "response_review='' ",
#                 "query_review='' ",
#                 "urls_review='' "
#                 "last_updated_at IS NULL"
#             ]) + ")"
        
#         sql += " ORDER BY timestamp DESC"
#         c.execute(sql, params)
#         rows = [dict(r) for r in c.fetchall()]
    
#     # fig = generate_graph(rows)
#     # fig_json = fig.to_plotly_json()
#     # Updated and return the graph 
#     # return Response(fig, cls=plotly.utils.PlotlyJSONEncoder, mimetype='application/json')
#     return generate_graph(rows)

@app.route('/update_table', methods=['POST'])
def update_table():
    # Read the latest changes or new log files 
    latest_logs = read_logs_from_files()
    # insert these into the database 
    with sqlite3.connect(DB_FILE) as conn:
        for log in latest_logs:
            insert_log(conn, log)
    
    return jsonify({"status": "ok"})

@app.route('/download_all', methods=['GET'])
def download_all():
    # --- Gather params ---
    file_type        = request.args.get('file_type', 'csv').lower()
    start_date       = request.args.get('start_date')
    end_date         = request.args.get('end_date')
    tool = request.args.get('tool', 'All')
    model = request.args.get('model', 'All')
    independent      = request.args.get('independent', 'All')
    response_reviews = request.args.getlist('response_review')
    query_reviews    = request.args.getlist('query_review')
    urls_reviews     = request.args.getlist('urls_review')
    review_status    = request.args.get('review_status', 'All')

    # --- Build & run query ---
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = "SELECT * FROM logs WHERE timestamp BETWEEN ? AND ?"
        params = [f"{start_date} 00:00:00,000", f"{end_date} 23:59:59,999"]
        
        if tool != 'All':
            sql += " AND tool=?",
            params.append(tool)
        if model != "All":
            sql += " AND model=?"
            params.append(model)
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
                "last_updated_at IS NOT NULL"
            ]) + ")"
        elif review_status == "Not Reviewed":
            sql += " AND (" + " AND ".join([
                "is_independent_question='' ",
                "response_review='' ",
                "query_review='' ",
                "urls_review='' ",
                "last_updated_at IS NULL"
            ]) + ")"

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
                'Timestamp','Query','Response', 'Tool', 'Model', 'Tester',
                'Independent?','Response Review','Query Review','URLs Review',
                'Last Updated By','Last Updated At'
            ])
            yield buf.getvalue()
            for log in rows:
                buf.seek(0); buf.truncate(0)
                writer.writerow([
                    log['timestamp'],
                    log['query'],
                    log['response'],
                    log['tool'],
                    log['model'],
                    log['tester'],
                    log['is_independent_question'],
                    log['response_review'],
                    log['query_review'],
                    log['urls_review'],
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
            'timestamp','query','response', 'tool', 'model', 'tester',
            'is_independent_question','response_review','query_review','urls_review',
            'last_updated_by','last_updated_at'
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

# ----------------------------------- Functions corresponding to Existing Authorization system --------------------------------------

# @app.route('/login')
# def login():
#     redirect_uri = os.getenv('REDIRECT_URI')
#     nonce = os.urandom(16).hex()
#     session['nonce'] = nonce
#     app.logger.info(f"Redirect URI: {redirect_uri}")
#     return oauth.cilogon.authorize_redirect(redirect_uri, nonce=nonce)

# @app.route('/authorize')
# def authorize():
#     try:
#         token = oauth.cilogon.authorize_access_token()
#         nonce = session.pop('nonce', None)
#         user = oauth.cilogon.parse_id_token(token, nonce=nonce)
#         user_info = oauth.cilogon.userinfo()
#         user['eppn'] = user_info.get('ePPN') or user_info.get('sub')
#         session['user'] = user

#         # if not in write list, kick them out
#         if not (is_write_user(user['eppn'])) and not (is_read_only_user(user['eppn'])):
#             ipaddr = request.headers.get('X-Forwarded-For', request.remote_addr)
#             unauth_logger.info(f"Unauthorized user {user['eppn']} from {ipaddr}")
#             flash('You are not authorized.', 'danger')
#             session.clear()
#             return redirect(url_for('unauthorized'))

#         # otherwise set read_only flag and continue
#         session['read_only'] = is_read_only_user(user['eppn'])
#         user_login_logger.info(f"User {user['eppn']} logged in. Read-only: {session['read_only']}")
#         flash('Authorization successful!', 'success')

#     except Exception as e:
#         # if anything went wrong in the try block, log & bounce back home
#         flash(f'Authorization failed: {e}', 'danger')
#         return redirect('/')   # <-- either redirect('/') or url_for('home_route')

#     # on success, send them to the real home page
#     return redirect('/')

# @app.route('/unauthorized')
# def unauthorized():
#     return render_template('unauthorized.html')

# @app.route('/logout')
# def logout():
#     session.clear()
#     return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True, host='gh3-internal.ccs.uky.edu', port=7865)

