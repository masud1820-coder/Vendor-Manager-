import os,sqlite3,json,hashlib,secrets
from functools import wraps
from flask import Flask,request,session,jsonify,send_from_directory
from werkzeug.security import generate_password_hash,check_password_hash
BASE=os.path.dirname(os.path.abspath(__file__))
app=Flask(__name__,static_folder='static',static_url_path='/static')
app.secret_key=os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax')
DB=os.environ.get('DATABASE_PATH',os.path.join(BASE,'charu.db'))
def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def init():
 c=db();c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT,username TEXT UNIQUE,password TEXT,role TEXT,approved INTEGER);CREATE TABLE IF NOT EXISTS vendors(id INTEGER PRIMARY KEY,name TEXT,holder TEXT,account TEXT,routing TEXT,branch TEXT,bank TEXT,mobile TEXT,head TEXT);CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,vendor_id INTEGER,year INTEGER,month INTEGER,amount REAL,head TEXT,FOREIGN KEY(vendor_id) REFERENCES vendors(id));CREATE TABLE IF NOT EXISTS banks(id INTEGER PRIMARY KEY,name TEXT UNIQUE);CREATE TABLE IF NOT EXISTS heads(id INTEGER PRIMARY KEY,name TEXT UNIQUE);CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);''')
 if not c.execute('SELECT 1 FROM vendors').fetchone():
  seed=json.load(open(os.path.join(BASE,'seed.json')));mapping={}
  for v in seed['vendors']:
   cur=c.execute('INSERT INTO vendors(name,holder,account,routing,branch,bank,mobile,head) VALUES(?,?,?,?,?,?,?,?)',tuple(v[k] for k in ('name','holder','account','routing','branch','bank','mobile','head')));mapping[v['account']+'|'+v['holder']]=cur.lastrowid
  for p in seed['payments']:
   if p['key'] in mapping:c.execute('INSERT INTO payments(vendor_id,year,month,amount,head) VALUES(?,?,?,?,?)',(mapping[p['key']],p['year'],p['month'],p['amount'],p['head']))
  for b in seed['banks']:c.execute('INSERT OR IGNORE INTO banks(name) VALUES(?)',(b,))
 c.execute("INSERT OR IGNORE INTO heads(name) VALUES('General')")
 c.commit();c.close()
init()
def auth(fn):
 @wraps(fn)
 def inner(*a,**kw):
  if not session.get('uid'):return jsonify(error='Login required'),401
  return fn(*a,**kw)
 return inner
def admin():return session.get('role')=='admin'
def query(sql,args=()):
 c=db();rows=[dict(r) for r in c.execute(sql,args).fetchall()];c.close();return rows
def execute(sql,args=()):
 c=db();cur=c.execute(sql,args);c.commit();id=cur.lastrowid;c.close();return id
@app.get('/')
def home():return send_from_directory(BASE,'index.html')
@app.get('/manifest.json')
def manifest():return send_from_directory(BASE,'manifest.json')
@app.get('/sw.js')
def sw():return send_from_directory(BASE,'sw.js')
@app.post('/api/register')
def register():
 d=request.json or {};name=str(d.get('name','')).strip();username=str(d.get('username','')).strip().lower();pw=str(d.get('password',''))
 if not name or len(username)<3 or len(pw)<8:return jsonify(error='Name, username (3+) and password (8+) required'),400
 c=db()
 try:
  c.execute('BEGIN IMMEDIATE');first=c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0
  c.execute('INSERT INTO users(name,username,password,role,approved) VALUES(?,?,?,?,?)',(name,username,generate_password_hash(pw),'admin' if first else 'user',1 if first else 0));c.commit()
 except sqlite3.IntegrityError:c.rollback();return jsonify(error='Username already exists'),409
 finally:c.close()
 return jsonify(message='Admin activated' if first else 'Waiting for admin approval',approved=first)
@app.post('/api/login')
def login():
 d=request.json or {};rows=query('SELECT * FROM users WHERE username=?',(str(d.get('username','')).strip().lower(),))
 if not rows or not check_password_hash(rows[0]['password'],str(d.get('password',''))):return jsonify(error='Incorrect login'),401
 u=rows[0]
 if not u['approved']:return jsonify(error='Waiting for admin approval'),403
 session.clear();session.update(uid=u['id'],role=u['role'],name=u['name']);return jsonify(name=u['name'],role=u['role'])
@app.post('/api/logout')
def logout():session.clear();return jsonify(ok=True)
@app.get('/api/me')
def me():return jsonify(name=session.get('name'),role=session.get('role'))
@app.get('/api/data')
@auth
def data():return jsonify(vendors=query('SELECT * FROM vendors ORDER BY name'),payments=query('SELECT * FROM payments ORDER BY year DESC,month DESC'),banks=query('SELECT * FROM banks ORDER BY name'),heads=query('SELECT * FROM heads ORDER BY name'),settings=query('SELECT * FROM settings'),users=query('SELECT id,name,username,role,approved FROM users ORDER BY id') if admin() else [])
@app.post('/api/save/<kind>')
@auth
def save(kind):
 d=request.json or {};tables={'vendors':['name','holder','account','routing','branch','bank','mobile','head'],'payments':['vendor_id','year','month','amount','head'],'banks':['name'],'heads':['name'],'settings':['key','value']}
 if kind not in tables:return jsonify(error='Invalid section'),400
 if kind=='settings' and not admin():return jsonify(error='Admin only'),403
 fields=tables[kind];vals=[d.get(k,'') for k in fields]
 if kind=='payments':
  try:
   vals[0]=int(vals[0]);vals[1]=int(vals[1]);vals[2]=int(vals[2]);vals[3]=float(vals[3]);assert 1<=vals[2]<=12 and vals[3]>=0
  except:return jsonify(error='Invalid payment values'),400
 if kind in ('banks','heads') and not str(vals[0]).strip():return jsonify(error='Name required'),400
 if kind=='vendors' and not str(vals[0]).strip():return jsonify(error='Vendor name required'),400
 try:
  if kind=='settings':execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',vals)
  elif d.get('id'):execute(f'UPDATE {kind} SET '+','.join(f'{k}=?' for k in fields)+' WHERE id=?',vals+[int(d['id'])])
  else:execute(f'INSERT INTO {kind}('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',vals)
 except sqlite3.IntegrityError:return jsonify(error='Duplicate or invalid record'),409
 return jsonify(ok=True)
@app.post('/api/delete/<kind>/<int:id>')
@auth
def delete(kind,id):
 if kind not in ('vendors','payments','banks','heads'):return jsonify(error='Invalid section'),400
 if kind=='vendors' and query('SELECT 1 FROM payments WHERE vendor_id=? LIMIT 1',(id,)):return jsonify(error='Vendor has payment history; keep it for records'),409
 execute(f'DELETE FROM {kind} WHERE id=?',(id,));return jsonify(ok=True)
@app.post('/api/approve/<int:id>')
@auth
def approve(id):
 if not admin():return jsonify(error='Admin only'),403
 execute('UPDATE users SET approved=1 WHERE id=?',(id,));return jsonify(ok=True)
if __name__=='__main__':app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=False)
