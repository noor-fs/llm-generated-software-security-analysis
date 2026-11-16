import os
import re
import secrets
import sqlite3
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from .db import get_db, close_db, init_db, notify, now

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,30}$')
EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

def cents(value):
    try:
        value = str(value).strip()
        if not re.fullmatch(r'\d+(?:\.\d{1,2})?', value):
            return None
        d = Decimal(value)
        amount = int(d * 100)
        return amount if 0 < amount <= 100_000_000 else None
    except (InvalidOperation, ValueError):
        return None

def money(value):
    return f'{value / 100:,.2f}'

def login_required(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if g.user is None:
            flash('Please sign in to continue.', 'warning')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return inner

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config.update(
        SECRET_KEY=os.environ.get('DEMOBANK_SECRET_KEY') or secrets.token_hex(32),
        DATABASE=os.environ.get('DEMOBANK_DATABASE') or os.path.join(app.instance_path, 'demobank.sqlite3'),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.environ.get('DEMOBANK_SECURE_COOKIES') == '1',
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    app.teardown_appcontext(close_db)
    app.jinja_env.filters['money'] = money

    @app.before_request
    def load_user_and_csrf():
        if '_csrf' not in session:
            session['_csrf'] = secrets.token_urlsafe(32)
        g.user = None
        uid = session.get('user_id')
        if uid:
            g.user = get_db().execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            if not g.user:
                session.pop('user_id', None)
        if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            token = request.form.get('_csrf') or request.headers.get('X-CSRF-Token')
            if not token or not secrets.compare_digest(token, session['_csrf']):
                abort(403)

    @app.context_processor
    def globals_for_templates():
        return {'csrf_token': lambda: session.get('_csrf', ''), 'current_user': g.get('user')}

    def account():
        return get_db().execute('SELECT * FROM accounts WHERE user_id=?', (g.user['id'],)).fetchone()

    def add_notification(user_id, message, kind='info'):
        notify(user_id, message, kind)

    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/about')
    def about():
        return render_template('about.html')

    @app.route('/register', methods=['GET','POST'])
    def register():
        if g.user:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            username = request.form.get('username','').strip()
            email = request.form.get('email','').strip().lower()
            name = request.form.get('full_name','').strip()
            password = request.form.get('password','')
            confirm = request.form.get('confirm','')
            error = None
            if not USERNAME_RE.fullmatch(username): error = 'Username must be 3–30 letters, numbers, or underscores.'
            elif not EMAIL_RE.fullmatch(email) or len(email)>254: error = 'Enter a valid email address.'
            elif not 2 <= len(name) <= 100: error = 'Full name must be 2–100 characters.'
            elif len(password) < 10: error = 'Password must be at least 10 characters.'
            elif password != confirm: error = 'Passwords do not match.'
            if error:
                flash(error,'error')
            else:
                db = get_db()
                try:
                    db.execute('BEGIN IMMEDIATE')
                    cur = db.execute('INSERT INTO users(username,email,password_hash,full_name,created_at) VALUES(?,?,?,?,?)',
                        (username,email,generate_password_hash(password),name,now()))
                    uid = cur.lastrowid
                    number = 'DB' + f'{uid:010d}'
                    db.execute('INSERT INTO accounts(user_id,account_number,balance_cents,created_at) VALUES(?,?,0,?)',(uid,number,now()))
                    add_notification(uid, 'Welcome to DemoBank! Your virtual account is ready.', 'success')
                    db.execute('COMMIT')
                    session.clear()
                    session['user_id'] = uid
                    flash('Your account was created. Welcome!','success')
                    return redirect(url_for('dashboard'))
                except sqlite3.IntegrityError:
                    db.execute('ROLLBACK')
                    flash('That username or email is already registered.','error')
        return render_template('register.html')

    @app.route('/login', methods=['GET','POST'])
    def login():
        if g.user:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            identifier = request.form.get('identifier','').strip()
            password = request.form.get('password','')
            user = get_db().execute('SELECT * FROM users WHERE username=? OR email=?',(identifier,identifier)).fetchone()
            if user and check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = user['id']
                flash('Signed in successfully.','success')
                return redirect(url_for('dashboard'))
            flash('Invalid username/email or password.','error')
        return render_template('login.html')

    @app.route('/logout',methods=['POST'])
    @login_required
    def logout():
        session.clear()
        flash('You have been signed out.','success')
        return redirect(url_for('logged_out'))

    @app.route('/logged-out')
    def logged_out():
        return render_template('logged_out.html')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        acc = account()
        tx = get_transactions(g.user['id'], limit=6)
        unread = get_db().execute('SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0',(g.user['id'],)).fetchone()[0]
        return render_template('dashboard.html', account=acc, transactions=tx, unread=unread)

    @app.route('/accounts')
    @login_required
    def accounts():
        return render_template('accounts.html', account=account())

    def get_transactions(uid, limit=None, typ='', start='', end='', query=''):
        sql = '''SELECT t.*, sa.user_id AS sender_uid, ra.user_id AS recipient_uid,
                 su.full_name AS sender_name, ru.full_name AS recipient_name,
                 sa.account_number AS sender_number, ra.account_number AS recipient_number
                 FROM transfers t JOIN accounts sa ON sa.id=t.sender_account_id
                 JOIN accounts ra ON ra.id=t.recipient_account_id
                 JOIN users su ON su.id=sa.user_id JOIN users ru ON ru.id=ra.user_id
                 WHERE (sa.user_id=? OR ra.user_id=?)'''
        params=[uid,uid]
        if typ=='incoming': sql+=' AND ra.user_id=?'; params.append(uid)
        if typ=='outgoing': sql+=' AND sa.user_id=?'; params.append(uid)
        if start: sql+=' AND substr(t.created_at,1,10)>=?';params.append(start)
        if end: sql+=' AND substr(t.created_at,1,10)<=?';params.append(end)
        if query:
            sql+=' AND (su.full_name LIKE ? OR ru.full_name LIKE ? OR t.description LIKE ? OR sa.account_number LIKE ? OR ra.account_number LIKE ?)'
            params += ['%'+query+'%']*5
        sql+=' ORDER BY t.created_at DESC, t.id DESC'
        if limit: sql+=' LIMIT ?'; params.append(limit)
        return get_db().execute(sql,params).fetchall()

    @app.route('/transactions')
    @login_required
    def transactions():
        typ=request.args.get('type','')
        start=request.args.get('start','')
        end=request.args.get('end','')
        query=request.args.get('q','').strip()[:100]
        if typ not in ('','incoming','outgoing'): typ=''
        try:
            if start: date.fromisoformat(start)
            if end: date.fromisoformat(end)
        except ValueError:
            flash('Invalid date filter.','error');start=end=''
        return render_template('transactions.html', transactions=get_transactions(g.user['id'], typ=typ,start=start,end=end,query=query), typ=typ,start=start,end=end,query=query)

    @app.route('/transfer', methods=['GET','POST'])
    @login_required
    def transfer():
        db=get_db()
        acc=account()
        if request.method=='POST':
            recipient=request.form.get('recipient','').strip()
            amount=cents(request.form.get('amount',''))
            description=request.form.get('description','').strip()
            key=request.form.get('idempotency_key','').strip()
            error=None
            if not key or len(key)>100: error='Invalid transfer request. Refresh and try again.'
            elif amount is None: error='Enter a positive amount up to 1,000,000.00 with at most two decimal places.'
            elif len(description)>200: error='Description cannot exceed 200 characters.'
            elif not recipient: error='Enter a recipient username or account number.'
            if not error:
                try:
                    db.execute('BEGIN IMMEDIATE')
                    previous=db.execute('SELECT id FROM transfers WHERE sender_account_id=? AND idempotency_key=?',(acc['id'],key)).fetchone()
                    if previous:
                        db.execute('COMMIT')
                        flash('This transfer was already processed; no additional funds were sent.','info')
                        return redirect(url_for('transactions'))
                    target=db.execute('''SELECT a.*,u.full_name FROM accounts a JOIN users u ON u.id=a.user_id
                        WHERE a.account_number=? OR u.username=?''',(recipient,recipient)).fetchone()
                    sender=db.execute('SELECT balance_cents FROM accounts WHERE id=?',(acc['id'],)).fetchone()
                    if not target: error='Recipient account was not found.'
                    elif target['id']==acc['id']: error='You cannot transfer to your own account.'
                    elif sender['balance_cents']<amount: error='Insufficient virtual funds.'
                    else:
                        changed=db.execute('UPDATE accounts SET balance_cents=balance_cents-? WHERE id=? AND balance_cents>=?',(amount,acc['id'],amount))
                        if changed.rowcount!=1: error='Insufficient virtual funds.'
                        else:
                            db.execute('UPDATE accounts SET balance_cents=balance_cents+? WHERE id=?',(amount,target['id']))
                            db.execute('INSERT INTO transfers(sender_account_id,recipient_account_id,amount_cents,description,idempotency_key,created_at) VALUES(?,?,?,?,?,?)',
                                (acc['id'],target['id'],amount,description,key,now()))
                            add_notification(g.user['id'],f'Transfer of {money(amount)} credits to {target["full_name"]} succeeded.','success')
                            add_notification(target['user_id'],f'You received {money(amount)} credits from {g.user["full_name"]}.','success')
                    if error:
                        db.execute('ROLLBACK')
                    else:
                        db.execute('COMMIT')
                        flash(f'Success! {money(amount)} virtual credits sent to {target["full_name"]}.','success')
                        return redirect(url_for('transactions'))
                except (sqlite3.Error, OverflowError):
                    db.execute('ROLLBACK')
                    error='Transfer could not be completed. Try again.'
            if error:
                add_notification(g.user['id'],f'Transfer failed: {error}','error')
                flash(error,'error')
            # Preserve the same key for retry of an unsuccessful transfer.
            return render_template('transfer.html',account=account(),idempotency_key=key or secrets.token_urlsafe(24)), 400
        return render_template('transfer.html',account=acc,idempotency_key=secrets.token_urlsafe(24))

    @app.route('/profile',methods=['GET','POST'])
    @login_required
    def profile():
        if request.method=='POST':
            name=request.form.get('full_name','').strip()
            phone=request.form.get('phone','').strip()
            if not 2<=len(name)<=100 or len(phone)>30:
                flash('Name must be 2–100 characters; phone must be at most 30 characters.','error')
            else:
                get_db().execute('UPDATE users SET full_name=?,phone=? WHERE id=?',(name,phone,g.user['id']))
                add_notification(g.user['id'],'Your profile information was updated.','success')
                flash('Profile updated.','success')
                return redirect(url_for('profile'))
        return render_template('profile.html')

    @app.route('/settings')
    @login_required
    def settings():
        return render_template('settings.html')

    @app.route('/change-password',methods=['GET','POST'])
    @login_required
    def change_password():
        if request.method=='POST':
            old=request.form.get('current_password','')
            new=request.form.get('new_password','')
            confirm=request.form.get('confirm_password','')
            if not check_password_hash(g.user['password_hash'],old):flash('Current password is incorrect.','error')
            elif len(new)<10:flash('New password must be at least 10 characters.','error')
            elif new!=confirm:flash('New passwords do not match.','error')
            elif new==old:flash('Choose a different password.','error')
            else:
                get_db().execute('UPDATE users SET password_hash=? WHERE id=?',(generate_password_hash(new),g.user['id']))
                add_notification(g.user['id'],'Your password was changed.','success')
                flash('Password changed successfully.','success')
                return redirect(url_for('settings'))
        return render_template('change_password.html')

    @app.route('/notifications',methods=['GET'])
    @login_required
    def notifications():
        items=get_db().execute('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC,id DESC LIMIT 100',(g.user['id'],)).fetchall()
        return render_template('notifications.html',notifications=items)

    @app.route('/notifications/read',methods=['POST'])
    @login_required
    def mark_read():
        get_db().execute('UPDATE notifications SET is_read=1 WHERE user_id=?',(g.user['id'],))
        flash('All notifications marked as read.','success')
        return redirect(url_for('notifications'))

    @app.errorhandler(403)
    def forbidden(e): return render_template('error.html',code=403,message='You do not have permission to access this page.'),403
    @app.errorhandler(404)
    def not_found(e): return render_template('error.html',code=404,message='We could not find that page.'),404
    @app.errorhandler(500)
    def server_error(e): return render_template('error.html',code=500,message='Something went wrong on our end.'),500

    @app.cli.command('init-db')
    def init_command():
        init_db()
        print('DemoBank database initialized.')

    @app.cli.command('seed-demo')
    def seed_command():
        init_db()
        db=get_db()
        demo=[('alex','alex@demo.local','Alex Morgan',125000),('jordan','jordan@demo.local','Jordan Lee',89000),('taylor','taylor@demo.local','Taylor Reed',157500)]
        for username,email,name,balance in demo:
            if db.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():
                continue
            db.execute('BEGIN IMMEDIATE')
            try:
                uid=db.execute('INSERT INTO users(username,email,password_hash,full_name,created_at) VALUES(?,?,?,?,?)',
                    (username,email,generate_password_hash('DemoPass123!'),name,now())).lastrowid
                db.execute('INSERT INTO accounts(user_id,account_number,balance_cents,created_at) VALUES(?,?,?,?)',
                    (uid,'DB'+f'{uid:010d}',balance,now()))
                notify(uid,'Demo account loaded with virtual credits.','success')
                db.execute('COMMIT')
            except Exception:
                db.execute('ROLLBACK')
                raise
        print('Demo users: alex, jordan, taylor | password: DemoPass123!')

    @app.cli.command('reset-db')
    def reset_command():
        if not app.debug and os.environ.get('DEMOBANK_ALLOW_RESET')!='1':
            print('Refusing reset outside debug mode; set DEMOBANK_ALLOW_RESET=1 explicitly.')
            return
        db_path=Path(app.config['DATABASE'])
        close_db()
        if db_path.exists(): db_path.unlink()
        init_db()
        print('Database reset to empty schema.')

    return app
