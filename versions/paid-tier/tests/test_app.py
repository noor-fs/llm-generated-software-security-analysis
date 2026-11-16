import sqlite3
import threading
from demobank.db import get_db
from .conftest import login, csrf


def test_public_pages(client):
    for path in ['/', '/about', '/login', '/register', '/does-not-exist']:
        res=client.get(path)
        assert res.status_code == (404 if path=='/does-not-exist' else 200)


def test_authentication_and_private_routes(client):
    for path in ['/dashboard','/accounts','/transfer','/transactions','/profile','/settings','/change-password','/notifications']:
        assert client.get(path).status_code==302
    assert b'Welcome back' in login(client).data
    assert client.get('/dashboard').status_code==200
    client.post('/logout',data={'_csrf':csrf(client)})
    assert client.get('/dashboard').status_code==302


def test_csrf_required(client):
    login(client)
    assert client.post('/transfer', data={'recipient':'jordan','amount':'1','idempotency_key':'x'}).status_code==403


def test_register_duplicate_and_new_user(client):
    client.get('/register')
    token=csrf(client)
    reg={'_csrf':token,'username':'newperson','email':'new@test.local','full_name':'New Person','password':'StrongPass123!','confirm':'StrongPass123!'}
    assert client.post('/register',data=reg,follow_redirects=True).status_code==200
    client.post('/logout',data={'_csrf':csrf(client)})
    assert b'already registered' in client.post('/register',data={**reg,'_csrf':csrf(client),'username':'ALEX'},follow_redirects=True).data


def test_transfer_success_repeat_and_authorization(client,app):
    login(client)
    form={'_csrf':csrf(client),'recipient':'jordan','amount':'10.25','description':'Lunch','idempotency_key':'once-only-1'}
    assert client.post('/transfer',data=form,follow_redirects=True).status_code==200
    with app.app_context():
        db=get_db()
        assert db.execute('SELECT balance_cents FROM accounts WHERE id=1').fetchone()[0]==8975
        assert db.execute('SELECT balance_cents FROM accounts WHERE id=2').fetchone()[0]==6025
        assert db.execute('SELECT COUNT(*) FROM transfers').fetchone()[0]==1
    assert b'already processed' in client.post('/transfer',data=form,follow_redirects=True).data
    with app.app_context():
        assert get_db().execute('SELECT COUNT(*) FROM transfers').fetchone()[0]==1
    assert b'Lunch' in client.get('/transactions').data
    client.post('/logout',data={'_csrf':csrf(client)})
    login(client,'taylor')
    assert b'Lunch' not in client.get('/transactions').data
    assert b'Lunch' not in client.get('/transactions?q=Lunch').data
    client.post('/logout',data={'_csrf':csrf(client)})
    login(client,'jordan')
    assert b'Lunch' in client.get('/transactions?type=incoming').data


def test_transfer_invalid_amounts(client,app):
    login(client)
    for i,amount in enumerate(['0','-1','0.001','abc','9999999999','100.999']):
        res=client.post('/transfer',data={'_csrf':csrf(client),'recipient':'jordan','amount':amount,'idempotency_key':f'bad-{i}'})
        assert res.status_code==400
    for recipient in ['alex','missing']:
        res=client.post('/transfer',data={'_csrf':csrf(client),'recipient':recipient,'amount':'5','idempotency_key':f'bad-{recipient}'})
        assert res.status_code==400
    res=client.post('/transfer',data={'_csrf':csrf(client),'recipient':'jordan','amount':'200','idempotency_key':'insufficient'})
    assert res.status_code==400
    with app.app_context():
        assert get_db().execute('SELECT COUNT(*) FROM transfers').fetchone()[0]==0


def test_password_change_and_profile(client):
    login(client)
    res=client.post('/profile',data={'_csrf':csrf(client),'full_name':'Alex Updated','phone':'12345'},follow_redirects=True)
    assert b'Alex Updated' in res.data
    res=client.post('/change-password',data={'_csrf':csrf(client),'current_password':'DemoPass123!','new_password':'NewStrongPass123!','confirm_password':'NewStrongPass123!'},follow_redirects=True)
    assert b'Password changed' in res.data
    client.post('/logout',data={'_csrf':csrf(client)})
    assert b'Invalid username' in login(client,password='DemoPass123!').data
    assert b'Welcome back' in login(client,password='NewStrongPass123!').data


def test_notifications_and_xss(client):
    login(client)
    description='<script>alert(1)</script>'
    client.post('/transfer',data={'_csrf':csrf(client),'recipient':'jordan','amount':'1','description':description,'idempotency_key':'xss-check'})
    page=client.get('/transactions').data
    assert b'&lt;script&gt;' in page
    assert description.encode() not in page
    assert client.post('/notifications/read',data={'_csrf':csrf(client)},follow_redirects=True).status_code==200


def test_concurrent_transfer_integrity(app):
    results=[]
    barrier=threading.Barrier(2)
    def worker(index):
        with app.test_client() as client:
            login(client)
            token=csrf(client)
            barrier.wait()
            response=client.post('/transfer',data={'_csrf':token,'recipient':'jordan','amount':'75','idempotency_key':f'concurrent-{index}'})
            results.append(response.status_code)
    threads=[threading.Thread(target=worker,args=(i,)) for i in range(2)]
    for t in threads:t.start()
    for t in threads:t.join(timeout=20)
    assert len(results)==2
    with app.app_context():
        db=get_db()
        assert db.execute('SELECT balance_cents FROM accounts WHERE id=1').fetchone()[0]==2500
        assert db.execute('SELECT balance_cents FROM accounts WHERE id=2').fetchone()[0]==12500
        assert db.execute('SELECT COUNT(*) FROM transfers').fetchone()[0]==1
