import pytest
from demobank import create_app
from demobank.db import init_db, get_db, now
from werkzeug.security import generate_password_hash

@pytest.fixture
def app(tmp_path):
    app=create_app({'TESTING': True, 'DATABASE': str(tmp_path/'test.sqlite3'), 'SECRET_KEY':'test-secret-for-isolated-tests'})
    with app.app_context():
        init_db()
        db=get_db()
        for name,balance in [('alex',10000),('jordan',5000),('taylor',3000)]:
            uid=db.execute('INSERT INTO users(username,email,password_hash,full_name,created_at) VALUES(?,?,?,?,?)',
                (name,f'{name}@test.local',generate_password_hash('DemoPass123!'),name.title(),now())).lastrowid
            db.execute('INSERT INTO accounts(user_id,account_number,balance_cents,created_at) VALUES(?,?,?,?)',
                (uid,'DB'+f'{uid:010d}',balance,now()))
    return app

@pytest.fixture
def client(app):return app.test_client()

def csrf(client):
    with client.session_transaction() as sess:
        return sess['_csrf']

def login(client,username='alex',password='DemoPass123!'):
    client.get('/login')
    return client.post('/login',data={'_csrf':csrf(client),'identifier':username,'password':password},follow_redirects=True)
