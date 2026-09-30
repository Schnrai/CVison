from flask import Flask, request, jsonify, render_template, session
import PyPDF2
import spacy
import re
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from functools import wraps
from collections import Counter
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash

# Load NLP model
nlp = spacy.load("en_core_web_sm")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-before-deploy")

DB_CONFIG = {
    "host": os.environ.get("MYSQL_HOST", "localhost"),
    "user": os.environ.get("MYSQL_USER", "root"),
    "password": os.environ.get("MYSQL_PASSWORD", ""),
    "database": os.environ.get("MYSQL_DATABASE", "cv_analyser"),
    "port": int(os.environ.get("MYSQL_PORT", "3306")),
}

DB_READY = False
DB_BACKEND = None
SQLITE_DB_PATH = Path(__file__).with_name("cv_analyser_local.db")

SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(180) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login_at DATETIME NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS user_activity (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        action VARCHAR(80) NOT NULL,
        details TEXT NULL,
        ip_address VARCHAR(64) NULL,
        user_agent VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_user_activity_user
            FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS analyses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        filename VARCHAR(255) NOT NULL,
        score INT NOT NULL,
        match_score INT NULL,
        total_skills INT NOT NULL,
        job_description_preview TEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_analyses_user
            FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE
    )
    """,
]

SQLITE_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login_at TEXT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS user_activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        details TEXT NULL,
        ip_address TEXT NULL,
        user_agent TEXT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        score INTEGER NOT NULL,
        match_score INTEGER NULL,
        total_skills INTEGER NOT NULL,
        job_description_preview TEXT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
]


def get_db_connection():
    ensure_database()
    if DB_BACKEND == "sqlite":
        connection = sqlite3.connect(SQLITE_DB_PATH)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    return mysql.connector.connect(**DB_CONFIG)


def get_server_connection():
    server_config = DB_CONFIG.copy()
    server_config.pop("database", None)
    return mysql.connector.connect(**server_config)


def ensure_database():
    global DB_READY, DB_BACKEND
    if DB_READY:
        return

    connection = None
    cursor = None

    try:
        connection = get_server_connection()
        cursor = connection.cursor()
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{DB_CONFIG['database']}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        cursor.execute(f"USE `{DB_CONFIG['database']}`")

        for statement in SCHEMA_STATEMENTS:
            cursor.execute(statement)

        connection.commit()
        DB_READY = True
        DB_BACKEND = "mysql"
    except Error:
        init_sqlite_database()
        DB_READY = True
        DB_BACKEND = "sqlite"
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def init_sqlite_database():
    connection = sqlite3.connect(SQLITE_DB_PATH)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        for statement in SQLITE_SCHEMA_STATEMENTS:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()


def normalize_query_for_backend(query):
    if DB_BACKEND == "sqlite":
        return query.replace("%s", "?")
    return query


def normalize_row(row):
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return dict(row)
    return row


def run_db_query(query, params=None, fetchone=False, fetchall=False, commit=False):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        if DB_BACKEND == "sqlite":
            cursor = connection.cursor()
        else:
            cursor = connection.cursor(dictionary=True)

        cursor.execute(normalize_query_for_backend(query), params or ())

        result = None
        if fetchone:
            result = normalize_row(cursor.fetchone())
        elif fetchall:
            result = [normalize_row(row) for row in cursor.fetchall()]

        if commit:
            connection.commit()
            result = cursor.lastrowid

        return result
    finally:
        if cursor:
            cursor.close()
        if connection:
            if DB_BACKEND == "sqlite" or connection.is_connected():
                connection.close()


def db_error_response(error=None):
    detail = str(error) if error else "Unknown MySQL connection error"
    return jsonify({
        "error": (
            "MySQL is not running or the credentials are incorrect. "
            "The app can use local fallback storage, but this request could not complete."
        ),
        "details": detail,
        "config": {
            "host": DB_CONFIG["host"],
            "port": DB_CONFIG["port"],
            "user": DB_CONFIG["user"],
            "database": DB_CONFIG["database"],
            "fallback_database": str(SQLITE_DB_PATH),
        },
    }), 503


def current_user_id():
    return session.get("user_id")


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not current_user_id():
            return jsonify({"error": "Please login to analyze and save activity"}), 401
        return view(*args, **kwargs)

    return wrapped_view


def log_activity(action, details=None, user_id=None):
    active_user_id = user_id or current_user_id()
    if not active_user_id:
        return

    try:
        run_db_query(
            """
            INSERT INTO user_activity (user_id, action, details, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                active_user_id,
                action,
                details,
                request.remote_addr,
                request.headers.get("User-Agent", "")[:255],
            ),
            commit=True,
        )
    except (Error, sqlite3.Error):
        pass


def public_user(user):
    if not user:
        return None

    created_at = user.get("created_at")
    last_login_at = user.get("last_login_at")

    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else created_at,
        "last_login_at": last_login_at.isoformat() if hasattr(last_login_at, "isoformat") else last_login_at,
    }


SKILLS_DICT = {
    "python": ["python"],
    "java": ["java"],
    "c": [" c ", "c programming"],
    "c++": ["c++", "cpp"],
    "c#": ["c#", "c sharp"],
    "javascript": ["javascript", "js", "ecmascript"],
    "typescript": ["typescript", "ts"],
    "html": ["html", "html5"],
    "css": ["css", "css3"],
    "sass": ["sass", "scss"],
    "bootstrap": ["bootstrap"],
    "tailwind css": ["tailwind", "tailwind css"],
    "react": ["react", "reactjs", "react.js"],
    "next.js": ["nextjs", "next.js"],
    "angular": ["angular"],
    "vue": ["vue", "vue.js", "vuejs"],
    "node.js": ["nodejs", "node.js", "node"],
    "express.js": ["express", "express.js"],
    "flask": ["flask"],
    "django": ["django"],
    "fastapi": ["fastapi"],
    "spring boot": ["spring boot", "springboot"],
    "php": ["php"],
    "laravel": ["laravel"],
    "sql": ["sql"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql", "postgres", "psql"],
    "mongodb": ["mongodb", "mongo db"],
    "redis": ["redis"],
    "firebase": ["firebase", "firestore"],
    "rest api": ["rest api", "restful api", "rest apis", "api development"],
    "graphql": ["graphql"],
    "git": ["git", "github", "gitlab", "bitbucket"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes", "k8s"],
    "aws": ["aws", "amazon web services"],
    "azure": ["azure", "microsoft azure"],
    "gcp": ["gcp", "google cloud", "google cloud platform"],
    "linux": ["linux", "ubuntu"],
    "ci/cd": ["ci/cd", "cicd", "continuous integration", "continuous deployment"],
    "jenkins": ["jenkins"],
    "devops": ["devops"],
    "machine learning": ["machine learning", "ml"],
    "deep learning": ["deep learning", "dl"],
    "artificial intelligence": ["artificial intelligence", "ai"],
    "data science": ["data science"],
    "data analysis": ["data analysis", "data analytics"],
    "pandas": ["pandas"],
    "numpy": ["numpy"],
    "scikit-learn": ["scikit-learn", "sklearn"],
    "tensorflow": ["tensorflow"],
    "pytorch": ["pytorch"],
    "nlp": ["nlp", "natural language processing"],
    "computer vision": ["computer vision"],
    "power bi": ["power bi", "powerbi"],
    "tableau": ["tableau"],
    "excel": ["excel", "ms excel", "microsoft excel"],
    "agile": ["agile", "scrum"],
    "jira": ["jira"],
    "testing": ["testing", "unit testing", "automation testing", "qa"],
    "selenium": ["selenium"],
    "figma": ["figma"],
    "ui/ux": ["ui/ux", "ui ux", "user experience", "user interface"],
    "communication": ["communication", "written communication", "verbal communication"],
    "leadership": ["leadership", "team leadership"],
    "problem solving": ["problem solving", "analytical thinking"],
    "api": ["api", "apis"],
    "microservices": ["microservices", "microservice"],
    "oop": ["oop", "object oriented programming", "object-oriented programming"],
    "data structures": ["data structures", "data structure", "dsa"],
    "algorithms": ["algorithms", "algorithm"],
    "mern stack": ["mern", "mern stack"],
    "redux": ["redux", "redux toolkit"],
    "material ui": ["material ui", "mui"],
    "git actions": ["github actions"],
    "postman": ["postman"],
    "jwt": ["jwt", "json web token", "json web tokens"],
    "oauth": ["oauth", "oauth2"],
    "cloud": ["cloud computing", "cloud"],
    "etl": ["etl"],
    "powerpoint": ["powerpoint", "ms powerpoint", "microsoft powerpoint"],
    "word": ["ms word", "microsoft word"],
    "teamwork": ["teamwork", "collaboration", "cross functional"],
    "time management": ["time management"],
}

STOPWORDS = {
    "about", "above", "after", "again", "against", "also", "and", "any",
    "are", "because", "been", "being", "between", "both", "can", "could",
    "day", "each", "few", "for", "from", "has", "have", "having", "into",
    "job", "more", "most", "must", "our", "over", "per", "role", "same",
    "should", "such", "that", "the", "their", "them", "then", "there",
    "these", "they", "this", "through", "with", "within", "will", "work",
    "years", "your", "candidate", "candidates", "company", "description",
    "etc", "excellent", "looking", "preferred", "required", "requirements",
    "responsibilities", "responsibility", "strong", "team", "using"
}

JOB_SECTION_WEIGHTS = {
    "must have": 1.45,
    "required": 1.35,
    "requirements": 1.35,
    "responsibilities": 1.15,
    "preferred": 0.85,
    "nice to have": 0.75,
}


def normalize_text(text):
    text = text.lower()
    replacements = {
        "react.js": "reactjs",
        "node.js": "nodejs",
        "next.js": "nextjs",
        "express.js": "expressjs",
        "c sharp": "c#",
        "c plus plus": "c++",
        "object-oriented": "object oriented",
        "ci cd": "cicd",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = re.sub(r"[\u2010-\u2015]", "-", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def alias_found(text, alias):
    clean_alias = normalize_text(alias).strip()
    if not clean_alias:
        return False

    if re.search(r"[+#./]", clean_alias):
        return clean_alias in text

    return re.search(rf"(?<![a-z0-9]){re.escape(clean_alias)}(?![a-z0-9])", text) is not None


def tokenize_meaningful(text):
    clean_text = re.sub(r"[^a-z0-9+#./ -]", " ", normalize_text(text))
    return [
        token for token in clean_text.split()
        if token not in STOPWORDS and len(token) > 2
    ]


def phrase_found(text, phrase):
    words = tokenize_meaningful(phrase)
    if not words:
        return False

    if len(words) == 1:
        return alias_found(text, words[0])

    phrase_pattern = r"\b" + r"[\s,;:/().-]+".join(re.escape(word) for word in words) + r"\b"
    if re.search(phrase_pattern, text):
        return True

    # Allow important two/three-word phrases to match when all words appear nearby.
    window_pattern = r"\b" + r"\b.{0,45}\b".join(re.escape(word) for word in words) + r"\b"
    return re.search(window_pattern, text) is not None


def job_line_weight(line):
    clean_line = normalize_text(line)
    for marker, weight in JOB_SECTION_WEIGHTS.items():
        if marker in clean_line:
            return weight
    return 1.0


# =========================
# SKILL EXTRACTION FUNCTION
# =========================
def extract_skills(text):
    clean_text = f" {normalize_text(text)} "
    found_skills = set()

    for main_skill, aliases in SKILLS_DICT.items():
        if any(alias_found(clean_text, alias) for alias in aliases):
            found_skills.add(main_skill)

    return sorted(found_skills)


def extract_job_keywords(job_description, limit=24):
    clean_text = normalize_text(job_description)
    doc = nlp(clean_text)
    candidates = Counter()

    for line in job_description.splitlines():
        weight = job_line_weight(line)
        line_text = normalize_text(line)
        if not line_text:
            continue

        for skill in extract_skills(line_text):
            candidates[skill] += 3.0 * weight

    for chunk in doc.noun_chunks:
        words = tokenize_meaningful(chunk.text)
        if 1 <= len(words) <= 4:
            candidates[" ".join(words)] += 1.8

    for token in doc:
        lemma = normalize_text(token.lemma_)
        if (
            token.pos_ in {"NOUN", "PROPN", "ADJ"}
            and lemma not in STOPWORDS
            and len(lemma) > 2
            and not token.is_stop
        ):
            candidates[lemma] += 1.0

    keywords = []
    for keyword, _ in candidates.most_common():
        if keyword not in keywords and not any(keyword in existing and keyword != existing for existing in keywords):
            keywords.append(keyword)
        if len(keywords) >= limit:
            break

    return keywords


def match_job_description(resume_skills, job_description, resume_text=""):
    jd_skills = extract_skills(job_description) if job_description else []
    jd_keywords = extract_job_keywords(job_description) if job_description else []

    resume_skill_set = set(resume_skills)
    jd_skill_set = set(jd_skills)
    matched_skills = sorted(resume_skill_set & jd_skill_set)
    missing_skills = sorted(jd_skill_set - resume_skill_set)
    resume_clean_text = f" {normalize_text(resume_text)} "
    matched_keywords = []
    for keyword in jd_keywords:
        if keyword in jd_skill_set:
            continue
        if phrase_found(resume_clean_text, keyword):
            matched_keywords.append(keyword)

    missing_keywords = [
        keyword for keyword in jd_keywords
        if keyword not in matched_keywords and keyword not in jd_skill_set
    ][:10]

    if not jd_skill_set and not jd_keywords:
        return {
            "job_skills": [],
            "matched_skills": [],
            "missing_skills": [],
            "matched_keywords": [],
            "missing_keywords": [],
            "match_score": None,
            "suggestions": []
        }

    keyword_pool = [keyword for keyword in jd_keywords if keyword not in jd_skill_set]
    skill_score = (len(matched_skills) / len(jd_skill_set)) * 100 if jd_skill_set else 0
    keyword_score = (len(matched_keywords) / len(keyword_pool)) * 100 if keyword_pool else 0

    if jd_skill_set and keyword_pool:
        match_score = round((skill_score * 0.7) + (keyword_score * 0.3))
    elif jd_skill_set:
        match_score = round(skill_score)
    else:
        match_score = round(keyword_score)

    suggestions = []

    if missing_skills:
        suggestions.append(
            "Add these job-required skills if you have experience with them: "
            + ", ".join(missing_skills)
        )

    if not matched_skills and jd_skill_set:
        suggestions.append("Add exact job-description skill keywords to your skills section and project bullets")

    if missing_keywords:
        suggestions.append(
            "Mirror important role language where truthful: "
            + ", ".join(missing_keywords[:5])
        )

    if matched_keywords:
        suggestions.append(
            "Role keywords already reflected in your resume: "
            + ", ".join(matched_keywords[:5])
        )

    if match_score < 50:
        suggestions.append("Tailor your resume summary and project bullets more closely to this job description")
    elif match_score < 75:
        suggestions.append("Improve job alignment by mentioning matching skills in your projects and experience")
    else:
        suggestions.append("Your resume skill set is strongly aligned with this job description")

    return {
        "job_skills": sorted(jd_skills),
        "matched_skills": matched_skills,
        "missing_skills": missing_skills,
        "matched_keywords": matched_keywords,
        "missing_keywords": missing_keywords,
        "match_score": match_score,
        "suggestions": suggestions
    }


# =========================
# RESUME SCORE FUNCTION
# =========================
def calculate_score(text, skills):

    score = 0

    suggestions = []

    text_lower = text.lower()
    words = re.findall(r"\b[a-zA-Z][a-zA-Z0-9+#.-]*\b", text_lower)
    word_count = len(words)
    line_count = len([line for line in text.splitlines() if line.strip()])

    section_patterns = {
        "experience": r"\b(experience|work experience|employment|internship|internships)\b",
        "projects": r"\b(projects?|portfolio)\b",
        "education": r"\b(education|degree|university|college|bachelor|master|b\.tech|m\.tech)\b",
        "skills": r"\b(skills?|technical skills|technologies|tools)\b",
        "achievements": r"\b(achievements?|awards?|certifications?|certificates?)\b"
    }

    action_verbs = [
        "built", "created", "developed", "designed", "implemented", "deployed",
        "optimized", "improved", "reduced", "increased", "automated", "led",
        "managed", "launched", "integrated", "analyzed", "delivered"
    ]

    impact_patterns = [
        r"\b\d+(\.\d+)?\s?%",
        r"\b\d+\+?\s?(users|clients|customers|students|requests|records|rows|apis|features|pages)\b",
        r"\b(rs\.?|inr|\$)\s?\d+",
        r"\b\d+(\.\d+)?\s?(x|times)\b",
        r"\b(reduced|increased|improved|optimized|saved|boosted)\b.{0,40}\b\d+"
    ]

    contact_patterns = [
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        r"(\+?\d[\d\s().-]{8,}\d)",
        r"github\.com/[\w.-]+",
        r"linkedin\.com/in/[\w.-]+"
    ]

    # Technical skills: max 25. High scores need strong breadth, not just 5 words.
    skill_count = len(skills)
    if skill_count >= 12:
        score += 25
    elif skill_count >= 9:
        score += 20
    elif skill_count >= 6:
        score += 15
    elif skill_count >= 3:
        score += 8
        suggestions.append("Add more relevant technical skills and tools")
    else:
        score += 3
        suggestions.append("Add a stronger technical skills section")

    # Core resume sections: max 20.
    section_score = 0
    for section, pattern in section_patterns.items():
        if re.search(pattern, text_lower):
            section_score += 4
        else:
            suggestions.append(f"Add a clear {section} section")
    score += section_score

    # Quantified impact: max 20. This makes a 90+ score difficult without evidence.
    impact_hits = 0
    for pattern in impact_patterns:
        impact_hits += len(re.findall(pattern, text_lower))

    if impact_hits >= 5:
        score += 20
    elif impact_hits >= 3:
        score += 15
    elif impact_hits >= 1:
        score += 8
        suggestions.append("Add more measurable results such as percentages, user counts, or performance gains")
    else:
        suggestions.append("Quantify achievements with numbers and outcomes")

    # Action-oriented experience/project bullets: max 10.
    action_hits = sum(1 for verb in action_verbs if re.search(rf"\b{verb}\b", text_lower))
    if action_hits >= 8:
        score += 10
    elif action_hits >= 5:
        score += 7
    elif action_hits >= 2:
        score += 4
        suggestions.append("Use stronger action verbs in project and experience bullet points")
    else:
        suggestions.append("Describe work using action verbs like built, deployed, optimized, and improved")

    # Contact and professional links: max 10.
    contact_hits = sum(1 for pattern in contact_patterns if re.search(pattern, text_lower))
    score += min(contact_hits * 2.5, 10)

    if "github.com" not in text_lower:
        suggestions.append("Add GitHub profile link")

    if "linkedin.com/in/" not in text_lower:
        suggestions.append("Add LinkedIn profile link")

    # Resume substance and formatting: max 15.
    if 450 <= word_count <= 900:
        score += 10
    elif 300 <= word_count < 450 or 900 < word_count <= 1200:
        score += 6
        suggestions.append("Improve resume length; aim for a focused one-page resume with enough detail")
    else:
        score += 2
        suggestions.append("Resume content is too short or too long for a strong score")

    if line_count >= 18:
        score += 5
    else:
        suggestions.append("Use clear bullet points and separate lines for readability")

    # Caps prevent thin resumes from reaching high scores through keyword stuffing.
    if not re.search(section_patterns["projects"], text_lower):
        score = min(score, 70)

    if not re.search(section_patterns["experience"], text_lower):
        score = min(score, 75)

    if impact_hits < 3:
        score = min(score, 82)

    if skill_count < 8:
        score = min(score, 78)

    if word_count < 300:
        score = min(score, 65)

    return round(min(score, 100)), list(dict.fromkeys(suggestions))


# =========================
# HOME ROUTE
# =========================
@app.route('/')
def home():
    return render_template("index.html")


# =========================
# TEST ROUTE
# =========================
@app.route('/test')
def test():
    return jsonify({
        "message": "API working perfectly"
    })


@app.route('/api/db/status')
def db_status():
    try:
        ensure_database()
    except (Error, sqlite3.Error) as exc:
        return db_error_response(exc)

    return jsonify({
        "message": (
            "MySQL connected and schema is ready"
            if DB_BACKEND == "mysql"
            else "MySQL is not running, using local fallback database"
        ),
        "backend": DB_BACKEND,
        "config": {
            "host": DB_CONFIG["host"],
            "port": DB_CONFIG["port"],
            "user": DB_CONFIG["user"],
            "database": DB_CONFIG["database"],
            "fallback_database": str(SQLITE_DB_PATH),
        },
    })


# =========================
# AUTH ROUTES
# =========================
@app.route('/api/auth/me')
def auth_me():
    if not current_user_id():
        return jsonify({"user": None})

    try:
        user = run_db_query(
            "SELECT id, name, email, created_at, last_login_at FROM users WHERE id = %s",
            (current_user_id(),),
            fetchone=True,
        )
    except (Error, sqlite3.Error) as exc:
        return db_error_response(exc)

    if not user:
        session.clear()
        return jsonify({"user": None})

    return jsonify({"user": public_user(user)})


@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if len(name) < 2:
        return jsonify({"error": "Please enter your full name"}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Please enter a valid email address"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    try:
        existing = run_db_query(
            "SELECT id FROM users WHERE email = %s",
            (email,),
            fetchone=True,
        )
        if existing:
            return jsonify({"error": "This email is already registered"}), 409

        user_id = run_db_query(
            "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)",
            (name, email, generate_password_hash(password)),
            commit=True,
        )
        session["user_id"] = user_id
        log_activity("signup", "Account created", user_id)
        user = run_db_query(
            "SELECT id, name, email, created_at, last_login_at FROM users WHERE id = %s",
            (user_id,),
            fetchone=True,
        )
    except (Error, sqlite3.Error) as exc:
        return db_error_response(exc)

    return jsonify({"message": "Account created successfully", "user": public_user(user)})


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        user = run_db_query(
            "SELECT id, name, email, password_hash, created_at, last_login_at FROM users WHERE email = %s",
            (email,),
            fetchone=True,
        )
        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "Invalid email or password"}), 401

        session["user_id"] = user["id"]
        run_db_query(
            "UPDATE users SET last_login_at = %s WHERE id = %s",
            (datetime.utcnow(), user["id"]),
            commit=True,
        )
        log_activity("login", "User logged in", user["id"])
        user = run_db_query(
            "SELECT id, name, email, created_at, last_login_at FROM users WHERE id = %s",
            (user["id"],),
            fetchone=True,
        )
    except (Error, sqlite3.Error) as exc:
        return db_error_response(exc)

    return jsonify({"message": "Logged in successfully", "user": public_user(user)})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    log_activity("logout", "User logged out")
    session.clear()
    return jsonify({"message": "Logged out successfully"})


@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    new_password = data.get("new_password", "")

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"error": "Please enter a valid registered email"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    try:
        user = run_db_query(
            "SELECT id FROM users WHERE email = %s",
            (email,),
            fetchone=True,
        )
        if not user:
            return jsonify({"error": "No account exists for this email"}), 404

        run_db_query(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (generate_password_hash(new_password), user["id"]),
            commit=True,
        )
        log_activity("password_reset", "Password reset from forgot password form", user["id"])
    except (Error, sqlite3.Error) as exc:
        return db_error_response(exc)

    return jsonify({"message": "Password updated. You can login now."})


# =========================
# UPLOAD RESUME ROUTE
# =========================
@app.route('/upload', methods=['POST'])
@login_required
def upload():

    # Check file exists
    if 'file' not in request.files:
        return jsonify({
            "error": "No file uploaded"
        })

    file = request.files['file']
    job_description = request.form.get("job_description", "").strip()

    # Check filename
    if file.filename == '':
        return jsonify({
            "error": "No selected file"
        })

    # Validate PDF
    if not file.filename.lower().endswith('.pdf'):
        return jsonify({
            "error": "Only PDF files are allowed"
        })

    # Read PDF safely
    try:
        pdf = PyPDF2.PdfReader(file)

    except Exception:
        return jsonify({
            "error": "Invalid or corrupted PDF"
        })

    # Extract text
    text = ""

    for page in pdf.pages:

        extracted = page.extract_text()

        if extracted:
            text += extracted

    if not text.strip():
        return jsonify({
            "error": "No readable text found in this PDF"
        })

    # Extract skills
    skills = extract_skills(text)

    # Match resume with job description
    job_match = match_job_description(skills, job_description, text)

    # Calculate score
    score, suggestions = calculate_score(text, skills)
    suggestions = list(dict.fromkeys(suggestions + job_match["suggestions"]))

    try:
        run_db_query(
            """
            INSERT INTO analyses
                (user_id, filename, score, match_score, total_skills, job_description_preview)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                current_user_id(),
                file.filename[:255],
                score,
                job_match["match_score"],
                len(skills),
                job_description[:500],
            ),
            commit=True,
        )
        log_activity(
            "resume_analysis",
            f"Analyzed {file.filename}; score={score}; match={job_match['match_score']}"
        )
    except (Error, sqlite3.Error) as exc:
        return db_error_response(exc)

    # Final response
    return jsonify({

        "message": "Resume analyzed successfully",

        "skills": skills,

        "total_skills": len(skills),

        "score": score,

        "suggestions": suggestions,

        "job_match": job_match,

        "preview": text[:500]

    })


# =========================
# RUN FLASK APP
# =========================
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
