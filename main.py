import streamlit as st
import sqlite3
import hashlib
import secrets
import string
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone, timedelta
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import requests
from io import StringIO
import time

# Page config
st.set_page_config(
    page_title="Secure Password Manager",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="auto",
    menu_items={
        'Get Help': None,
        'Report a Bug': None,
        'About': None
    }
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main > div {
        padding-top: 2rem;
    }
    
    .password-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        margin: 10px 0;
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
        backdrop-filter: blur(4px);
        border: 1px solid rgba(255, 255, 255, 0.18);
        color: white;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #ff6b6b 0%, #4ecdc4 100%);
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        color: white;
        margin: 5px;
    }
    
    .strength-bar {
        height: 20px;
        border-radius: 10px;
        background: #e0e0e0;
        overflow: hidden;
        margin: 5px 0;
    }
    
    .strength-fill {
        height: 100%;
        transition: width 0.3s ease;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: bold;
    }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #2c3e50 0%, #3498db 100%);
    }
    
    .stButton button {
        width: 100%;
        border-radius: 20px;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
</style>
""", unsafe_allow_html=True)

# Configuration
DB_FILE = "passwords.db"
SALT_FILE = "salt.salt"
MASTER_FILE = "master.hash"

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'key' not in st.session_state:
    st.session_state.key = None
if 'passwords' not in st.session_state:
    st.session_state.passwords = []
if 'search_query' not in st.session_state:
    st.session_state.search_query = ""
if 'generated_password' not in st.session_state:
    st.session_state.generated_password = None

class PasswordManager:
    def __init__(self):
        self.init_files()
        self.init_db()
    
    def init_files(self):
        if not os.path.exists(SALT_FILE):
            with open(SALT_FILE, 'wb') as f:
                f.write(os.urandom(16))
    
    def init_db(self):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT NOT NULL UNIQUE,
            username TEXT,
            email TEXT,
            password BLOB NOT NULL,
            website_url TEXT,
            category TEXT DEFAULT 'General',
            notes TEXT,
            tags TEXT,
            created_at TEXT,
            last_updated TEXT,
            last_accessed TEXT,
            is_favorite INTEGER DEFAULT 0,
            strength_score INTEGER DEFAULT 0
        )''')
        conn.commit()
        conn.close()
    
    # Master password functions
    def set_master_password(self, master_pwd):
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac('sha256', master_pwd.encode(), salt, 200_000)
        with open(MASTER_FILE, 'wb') as f:
            f.write(salt + dk)
    
    def verify_master_password(self, master_pwd):
        if not os.path.exists(MASTER_FILE):
            return False
        data = open(MASTER_FILE, 'rb').read()
        salt = data[:16]
        stored = data[16:]
        dk = hashlib.pbkdf2_hmac('sha256', master_pwd.encode(), salt, 200_000)
        return dk == stored
    
    def derive_key(self, master_pwd):
        salt = open(SALT_FILE, 'rb').read()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
        return base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
    
    # encrypt / decrypt
    def encrypt_text(self, plain_text, key):
        return Fernet(key).encrypt(plain_text.encode())
    
    def decrypt_text(self, encrypted_text, key):
        return Fernet(key).decrypt(encrypted_text).decode()
    
    # password utilities
    def calculate_password_strength(self, password):
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 25
        else:
            feedback.append("Use at least 8 characters")
            
        if len(password) >= 12:
            score += 20
        else:
            feedback.append("Consider using 12+ characters")
            
        if any(c.isupper() for c in password):
            score += 15
        else:
            feedback.append("Add uppercase letters")
            
        if any(c.islower() for c in password):
            score += 10
        else:
            feedback.append("Add lowercase letters") 
            
        if any(c.isdigit() for c in password):
            score += 15
        else:
            feedback.append("Add numbers")
            
        if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password):
            score += 15
        else:
            feedback.append("Add special characters")
        
        return min(score, 100), feedback
    
    def check_password_breach(self, password):
        # Uses k-anonymity API from haveibeenpwned
        try:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
            if response.status_code == 200:
                return suffix in response.text
            return False
        except:
            return False
    
    def generate_password(self, length=16, include_upper=True, include_lower=True, 
                         include_digits=True, include_symbols=True):
        chars = ""
        if include_lower:
            chars += string.ascii_lowercase
        if include_upper:
            chars += string.ascii_uppercase
        if include_digits:
            chars += string.digits
        if include_symbols:
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        if not chars:
            return None
            
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    # DB operations
    def add_password(self, account, username, email, password, website_url, 
                    category, notes, tags, key):
        encrypted_password = self.encrypt_text(password, key)
        strength_score, _ = self.calculate_password_strength(password)
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        c.execute("""INSERT OR REPLACE INTO passwords 
                    (account, username, email, password, website_url, category, 
                     notes, tags, created_at, last_updated, strength_score) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM passwords WHERE account=?), ?), ?, ?)""",
                 (account, username, email, encrypted_password, website_url,
                  category, notes, tags, account, now, now, strength_score))
        conn.commit()
        conn.close()
    
    def get_all_passwords(self, key):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM passwords ORDER BY account")
        rows = c.fetchall()
        conn.close()
        
        passwords = []
        for row in rows:
            try:
                decrypted_password = self.decrypt_text(row[4], key)
                passwords.append({
                    'id': row[0],
                    'account': row[1],
                    'username': row[2] or '',
                    'email': row[3] or '',
                    'password': decrypted_password,
                    'website_url': row[5] or '',
                    'category': row[6] or 'General',
                    'notes': row[7] or '',
                    'tags': row[8] or '',
                    'created_at': row[9],
                    'last_updated': row[10],
                    'last_accessed': row[11],
                    'is_favorite': bool(row[12]),
                    'strength_score': row[13] or 0
                })
            except Exception:
                # if decryption fails, skip entry (likely wrong key)
                continue
        
        return passwords
    
    def delete_password(self, password_id):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
        conn.commit()
        conn.close()
    
    def export_passwords(self, passwords):
        export_data = []
        for pwd in passwords:
            export_data.append({
                'Account': pwd['account'],
                'Username': pwd['username'],
                'Email': pwd['email'],
                'Password': pwd['password'],
                'Website': pwd['website_url'],
                'Category': pwd['category'],
                'Notes': pwd['notes'],
                'Tags': pwd['tags']
            })
        return export_data

# Initialize password manager
pm = PasswordManager()

# ------------------ Pages / UI ------------------
def login_page():
    st.markdown("""
    <div style='text-align: center; padding: 2rem;'>
        <h1>🔐 Secure Password Manager</h1>
        <p style='font-size: 1.1rem; color: #666;'>Your passwords, secured with PBKDF2 + Fernet</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("### 🔑 Master")
        master_password = st.text_input("Master Password", type="password", key="master_pwd")
        col_login, col_setup = st.columns(2)
        with col_login:
            if st.button("🚀 Login"):
                if master_password:
                    if pm.verify_master_password(master_password):
                        st.session_state.authenticated = True
                        st.session_state.key = pm.derive_key(master_password)
                        st.success("✅ Login successful!")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error("❌ Invalid master password!")
                else:
                    st.warning("⚠️ Please enter master password")
        with col_setup:
            if not os.path.exists(MASTER_FILE):
                if st.button("🔧 Setup Master Password"):
                    if master_password:
                        if len(master_password) >= 8:
                            pm.set_master_password(master_password)
                            st.success("✅ Master password set! Please login.")
                        else:
                            st.error("❌ Master password must be at least 8 characters!")
                    else:
                        st.warning("⚠️ Please enter a master password")

def dashboard():
    passwords = pm.get_all_passwords(st.session_state.key)
    st.session_state.passwords = passwords
    
    st.markdown("# 🔐 Password Dashboard")
    col1, col2, col3, col4 = st.columns(4)
    
    total_passwords = len(passwords)
    weak_passwords = len([p for p in passwords if p['strength_score'] < 50])
    strong_passwords = len([p for p in passwords if p['strength_score'] >= 80])
    avg_strength = sum(p['strength_score'] for p in passwords) / len(passwords) if passwords else 0
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{total_passwords}</h3>
            <p>Total Passwords</p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card" style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);">
            <h3>{weak_passwords}</h3>
            <p>Weak Passwords</p>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card" style="background: linear-gradient(135deg, #51cf66 0%, #40c057 100%);">
            <h3>{strong_passwords}</h3>
            <p>Strong Passwords</p>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <h3>{avg_strength:.0f}%</h3>
            <p>Avg Strength</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Charts
    if passwords:
        col1, col2 = st.columns(2)
        with col1:
            strength_ranges = {'Weak (0-49)': 0, 'Medium (50-79)': 0, 'Strong (80-100)': 0}
            for p in passwords:
                score = p['strength_score']
                if score < 50:
                    strength_ranges['Weak (0-49)'] += 1
                elif score < 80:
                    strength_ranges['Medium (50-79)'] += 1
                else:
                    strength_ranges['Strong (80-100)'] += 1
            fig = px.pie(values=list(strength_ranges.values()), 
                        names=list(strength_ranges.keys()),
                        title="Password Strength Distribution",
                        color_discrete_sequence=['#ff6b6b', '#ffd43b', '#51cf66'])
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            categories = {}
            for p in passwords:
                cat = p['category']
                categories[cat] = categories.get(cat, 0) + 1
            fig2 = px.bar(x=list(categories.keys()), 
                         y=list(categories.values()),
                         title="Passwords by Category",
                         color=list(categories.values()),
                         color_continuous_scale='viridis')
            st.plotly_chart(fig2, use_container_width=True)

def password_generator():
    st.markdown("## 🔑 Password Generator")
    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown("### Settings")
        length = st.slider("Password Length", 8, 64, 16)
        include_upper = st.checkbox("Uppercase Letters", value=True)
        include_lower = st.checkbox("Lowercase Letters", value=True)
        include_digits = st.checkbox("Numbers", value=True)
        include_symbols = st.checkbox("Special Characters", value=True)
        if st.button("🎲 Generate Password"):
            password = pm.generate_password(length, include_upper, include_lower, include_digits, include_symbols)
            if password:
                st.session_state.generated_password = password
                st.success("✅ Password generated!")
            else:
                st.error("❌ Please select at least one character type!")
    with col2:
        if st.session_state.generated_password:
            st.markdown("### Generated Password")
            password = st.session_state.generated_password
            st.code(password, language='text')
            strength_score, feedback = pm.calculate_password_strength(password)
            if strength_score < 50:
                color = "#ff6b6b"; strength_text = "Weak"
            elif strength_score < 80:
                color = "#ffd43b"; strength_text = "Medium"
            else:
                color = "#51cf66"; strength_text = "Strong"
            st.markdown(f"""
            <div class="strength-bar">
                <div class="strength-fill" style="width: {strength_score}%; background-color: {color};">
                    {strength_score}% - {strength_text}
                </div>
            </div>
            """, unsafe_allow_html=True)
            if pm.check_password_breach(password):
                st.error("⚠️ This password has been found in data breaches!")
            else:
                st.success("✅ Password not found in known breaches")
            if feedback:
                st.markdown("**Suggestions for improvement:**")
                for suggestion in feedback:
                    st.write(f"• {suggestion}")
            if st.button("📋 Copy to Clipboard"):
                st.success("Password copied! (Note: real clipboard operations may require browser integration)")
                st.balloons()

def add_password():
    st.markdown("## ➕ Add New Password")
    with st.form("add_password_form"):
        col1, col2 = st.columns(2)
        with col1:
            account = st.text_input("Account Name*", placeholder="e.g., Gmail, Facebook")
            username = st.text_input("Username", placeholder="john.doe")
            email = st.text_input("Email", placeholder="john@example.com")
            website_url = st.text_input("Website URL", placeholder="https://example.com")
        with col2:
            password = st.text_input("Password*", type="password")
            category = st.selectbox("Category", 
                                  ["General", "Social Media", "Work", "Banking", 
                                   "Shopping", "Entertainment", "Other"])
            tags = st.text_input("Tags", placeholder="work, important (comma-separated)")
            notes = st.text_area("Notes", placeholder="Additional information...")
        if password:
            strength_score, feedback = pm.calculate_password_strength(password)
            col_strength1, col_strength2 = st.columns([3, 1])
            with col_strength1:
                if strength_score < 50:
                    color = "#ff6b6b"; strength_text = "Weak"
                elif strength_score < 80:
                    color = "#ffd43b"; strength_text = "Medium"
                else:
                    color = "#51cf66"; strength_text = "Strong"
                st.markdown(f"""
                <div class="strength-bar">
                    <div class="strength-fill" style="width: {strength_score}%; background-color: {color};">
                        {strength_score}% - {strength_text}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            with col_strength2:
                if pm.check_password_breach(password):
                    st.error("⚠️ Breached!")
                else:
                    st.success("✅ Secure")
        submitted = st.form_submit_button("💾 Save Password")
        if submitted:
            if account and password:
                if not st.session_state.key:
                    st.error("Unlock app first!")
                else:
                    try:
                        pm.add_password(account, username, email, password, website_url,
                                      category, notes, tags, st.session_state.key)
                        st.success("✅ Password saved successfully!")
                        st.balloons()
                        time.sleep(0.5)
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Error saving password: {str(e)}")
            else:
                st.error("❌ Account name and password are required!")

def view_passwords():
    st.markdown("## 👀 View & Manage Passwords")
    passwords = st.session_state.passwords
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        search_query = st.text_input("🔍 Search passwords...", value=st.session_state.search_query,
                                   placeholder="Search by account, username, or category")
        st.session_state.search_query = search_query
    with col2:
        categories = ["All"] + sorted(list({p['category'] for p in passwords}))
        category_filter = st.selectbox("Filter by Category", categories)
    with col3:
        sort_by = st.selectbox("Sort by", ["Account", "Strength", "Date Added"])
    filtered_passwords = passwords
    if search_query:
        filtered_passwords = [p for p in filtered_passwords 
                            if search_query.lower() in p['account'].lower() or
                               search_query.lower() in p['username'].lower() or
                               search_query.lower() in p['category'].lower()]
    if category_filter != "All":
        filtered_passwords = [p for p in filtered_passwords if p['category'] == category_filter]
    if sort_by == "Account":
        filtered_passwords.sort(key=lambda x: x['account'].lower())
    elif sort_by == "Strength":
        filtered_passwords.sort(key=lambda x: x['strength_score'], reverse=True)
    elif sort_by == "Date Added":
        filtered_passwords.sort(key=lambda x: x['created_at'] or "", reverse=True)
    st.markdown(f"### Found {len(filtered_passwords)} passwords")
    for i, pwd in enumerate(filtered_passwords):
        with st.expander(f"🏢 {pwd['account']} ({pwd['category']})", expanded=False):
            col1, col2, col3 = st.columns([2, 2, 1])
            with col1:
                st.write(f"**👤 Username:** {pwd['username']}")
                st.write(f"**📧 Email:** {pwd['email']}")
                st.write(f"**🌐 Website:** {pwd['website_url']}")
                if pwd['tags']:
                    st.write(f"**🏷️ Tags:** {pwd['tags']}")
            with col2:
                st.write(f"**📝 Notes:** {pwd['notes']}")
                st.write(f"**📅 Created:** {pwd['created_at'][:10] if pwd['created_at'] else 'N/A'}")
                st.write(f"**🔄 Updated:** {pwd['last_updated'][:10] if pwd['last_updated'] else 'N/A'}")
            with col3:
                strength = pwd['strength_score']
                if strength < 50:
                    st.error(f"🔴 {strength}%")
                elif strength < 80:
                    st.warning(f"🟡 {strength}%")
                else:
                    st.success(f"🟢 {strength}%")
                if st.button("👁️ Show", key=f"show_{pwd['id']}"):
                    st.code(pwd['password'])
                if st.button("📋 Copy", key=f"copy_{pwd['id']}"):
                    st.success("Copied! (Real clipboard requires browser permissions)")
                if st.button("🗑️ Delete", key=f"delete_{pwd['id']}"):
                    pm.delete_password(pwd['id'])
                    st.success("Password deleted!")
                    st.rerun()

def security_audit():
    st.markdown("## 🛡️ Security Audit")
    passwords = st.session_state.passwords
    if not passwords:
        st.info("No passwords to audit. Add some passwords first!")
        return
    weak_passwords = [p for p in passwords if p['strength_score'] < 50]
    medium_passwords = [p for p in passwords if 50 <= p['strength_score'] < 80]
    strong_passwords = [p for p in passwords if p['strength_score'] >= 80]
    password_counts = {}
    for p in passwords:
        pwd = p['password']
        password_counts.setdefault(pwd, []).append(p['account'])
    duplicates = {pwd: accounts for pwd, accounts in password_counts.items() if len(accounts) > 1}
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=90)
    old_passwords = []
    for p in passwords:
        if p['created_at']:
            try:
                created_date = datetime.fromisoformat(p['created_at'].replace('Z', '+00:00'))
                if created_date < cutoff_date:
                    old_passwords.append(p)
            except:
                continue
    total_passwords = len(passwords)
    security_score = 0
    if total_passwords > 0:
        strong_ratio = len(strong_passwords) / total_passwords
        duplicate_penalty = len(duplicates) / total_passwords
        old_penalty = len(old_passwords) / total_passwords
        security_score = max(0, (strong_ratio * 100) - (duplicate_penalty * 30) - (old_penalty * 20))
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if security_score >= 80:
            st.success(f"🟢 Security Score: {security_score:.0f}%")
        elif security_score >= 60:
            st.warning(f"🟡 Security Score: {security_score:.0f}%")
        else:
            st.error(f"🔴 Security Score: {security_score:.0f}%")
    with col2:
        st.metric("Weak Passwords", len(weak_passwords))
    with col3:
        st.metric("Duplicate Passwords", len(duplicates))
    with col4:
        st.metric("Old Passwords (90+ days)", len(old_passwords))
    tab1, tab2, tab3, tab4 = st.tabs(["🔴 Weak Passwords", "👥 Duplicates", "⏰ Old Passwords", "📊 Analytics"])
    with tab1:
        if weak_passwords:
            st.warning(f"Found {len(weak_passwords)} weak passwords:")
            for pwd in weak_passwords:
                st.write(f"• **{pwd['account']}** - Strength: {pwd['strength_score']}%")
        else:
            st.success("✅ No weak passwords found!")
    with tab2:
        if duplicates:
            st.warning(f"Found {len(duplicates)} duplicate password entries:")
            for pwd, accounts in duplicates.items():
                st.write(f"• Used by: {', '.join(accounts)}")
        else:
            st.success("✅ No duplicate passwords found!")
    with tab3:
        if old_passwords:
            st.warning(f"Found {len(old_passwords)} old passwords:")
            for pwd in old_passwords:
                try:
                    days_old = (datetime.now(timezone.utc) - datetime.fromisoformat(pwd['created_at'].replace('Z', '+00:00'))).days
                except:
                    days_old = "N/A"
                st.write(f"• **{pwd['account']}** - {days_old} days old")
        else:
            st.success("✅ All passwords are recent!")
    with tab4:
        ages = []
        for p in passwords:
            if p['created_at']:
                try:
                    created_date = datetime.fromisoformat(p['created_at'].replace('Z', '+00:00'))
                    age_days = (datetime.now(timezone.utc) - created_date).days
                    ages.append(age_days)
                except:
                    continue
        if ages:
            fig = px.histogram(x=ages, nbins=20, title="Password Age Distribution (Days)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Not enough data for analytics.")

def export_import():
    st.markdown("## 📤📥 Export & Import")
    passwords = st.session_state.passwords
    st.markdown("### 📤 Export Passwords")
    export_format = st.selectbox("Export Format", ["JSON", "CSV"])
    if st.button("📤 Export All Passwords"):
        if passwords:
            export_data = pm.export_passwords(passwords)
            if export_format == "JSON":
                json_str = json.dumps(export_data, indent=2)
                st.download_button(
                    label="💾 Download JSON",
                    data=json_str,
                    file_name=f"passwords_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            else:
                df = pd.DataFrame(export_data)
                csv_str = df.to_csv(index=False)
                st.download_button(
                    label="💾 Download CSV",
                    data=csv_str,
                    file_name=f"passwords_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        else:
            st.info("No passwords to export.")
    st.markdown("---")
    st.markdown("### 📥 Import Passwords")
    upload = st.file_uploader("Upload JSON or CSV (plaintext backup)", type=["json", "csv"])
    if upload:
        try:
            if upload.type == "application/json" or upload.name.endswith(".json"):
                loaded = json.load(upload)
                # Expecting list of dicts with keys: Account, Username, Email, Password, Website, Category, Notes, Tags
                for item in loaded:
                    if 'Account' in item and 'Password' in item:
                        pm.add_password(
                            item['Account'],
                            item.get('Username', ''),
                            item.get('Email', ''),
                            item['Password'],
                            item.get('Website', ''),
                            item.get('Category', 'General'),
                            item.get('Notes', ''),
                            item.get('Tags', ''),
                            st.session_state.key
                        )
                st.success("Imported JSON backup ✅")
                st.experimental_rerun()
            else:
                # CSV
                df = pd.read_csv(upload)
                for _, row in df.iterrows():
                    if 'Account' in row and 'Password' in row:
                        pm.add_password(
                            row['Account'],
                            row.get('Username', ''),
                            row.get('Email', ''),
                            row['Password'],
                            row.get('Website', ''),
                            row.get('Category', 'General'),
                            row.get('Notes', ''),
                            row.get('Tags', ''),
                            st.session_state.key
                        )
                st.success("Imported CSV backup ✅")
                st.experimental_rerun()
        except Exception as e:
            st.error(f"Import failed: {e}")

# ------------------ Main Router ------------------
def main():
    # Sidebar navigation and master controls
    with st.sidebar:
        st.image("https://cdn-icons-png.flaticon.com/512/2910/2910768.png", width=80)
        st.title("🔑 Vault")
        if not st.session_state.authenticated:
            st.info("Please login from the main area")
        else:
            if st.button("🔒 Lock Vault"):
                st.session_state.authenticated = False
                st.session_state.key = None
                st.success("Vault locked")
                st.rerun()
        st.divider()
        st.markdown("### Menu")
        menu = ["📊 Dashboard", "➕ Add Password", "👀 View Passwords",
                "🎲 Password Generator", "🛡️ Security Audit", "📤📥 Export/Import"]
        choice = st.radio("", menu, index=0)
        st.divider()
        st.markdown("### Quick Tools")
        if st.button("🔄 Generate Quick Password (12 chars)"):
            st.session_state.generated_password = pm.generate_password(12, True, True, True, True)
            st.success("Generated — check Password Generator")
        st.markdown(" ")
        st.caption("Security: PBKDF2 (200k) + Fernet; do not run on untrusted servers.")

    # Page router
    if not st.session_state.authenticated:
        login_page()
    else:
        # refresh passwords into session
        if st.session_state.key:
            st.session_state.passwords = pm.get_all_passwords(st.session_state.key)
        if choice == "📊 Dashboard":
            dashboard()
        elif choice == "➕ Add Password":
            add_password()
        elif choice == "👀 View Passwords":
            view_passwords()
        elif choice == "🎲 Password Generator":
            password_generator()
        elif choice == "🛡️ Security Audit":
            security_audit()
        elif choice == "📤📥 Export/Import":
            export_import()

if __name__ == "__main__":
    main()  
