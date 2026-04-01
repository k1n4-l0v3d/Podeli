from flask import Flask, request, jsonify, send_from_directory, session
from dotenv import load_dotenv
from db import get_conn
from werkzeug.security import generate_password_hash, check_password_hash
import os, uuid, time, json as _json

load_dotenv()

app = Flask(__name__, static_folder="static")

def run_migrations():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""ALTER TABLE orders ADD COLUMN IF NOT EXISTS items JSONB""")
        conn.commit()

run_migrations()
app.secret_key = os.getenv("SECRET_KEY", "super-secret-dev-key-change-me")
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(f): return '.' in f and f.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def current_user_id(): return session.get('user_id')

def require_auth():
    if not current_user_id(): return jsonify({"error": "Не авторизован"}), 401

def require_admin():
    if not current_user_id(): return jsonify({"error": "Не авторизован"}), 401
    if not session.get('is_admin'): return jsonify({"error": "Нет прав"}), 403

def check_not_kicked():
    uid = current_user_id()
    if not uid: return None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT session_invalidated_at FROM users WHERE id=%s", (uid,))
            row = cur.fetchone()
    if not row: return jsonify({"error": "Не найден"}), 401
    inv = row['session_invalidated_at']
    lt = session.get('login_time')
    if inv and lt and inv.timestamp() > lt:
        session.clear()
        return jsonify({"error": "Сессия завершена администратором"}), 401

@app.route("/")
def index(): return send_from_directory("static", "index.html")

@app.route("/static/uploads/<path:filename>")
def uploaded_file(filename): return send_from_directory(UPLOAD_FOLDER, filename)

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    d = request.json
    username = d.get("username","").strip()
    password = d.get("password","").strip()
    if not username or not password: return jsonify({"error":"Введи имя и пароль"}), 400
    if len(username) < 2: return jsonify({"error":"Имя слишком короткое"}), 400
    if len(password) < 4: return jsonify({"error":"Пароль минимум 4 символа"}), 400
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO users (username,password_hash) VALUES (%s,%s) RETURNING id,username,is_admin",
                            (username, generate_password_hash(password)))
                u = cur.fetchone()
            conn.commit()
        session.update({'user_id':str(u['id']),'username':u['username'],'display_name':'',
                        'phone':'','bank':'','is_admin':bool(u['is_admin']),'login_time':time.time()})
        return jsonify({"ok":True,"username":u['username'],"display_name":'','phone':'','bank':'','is_admin':False}), 201
    except: return jsonify({"error":"Имя уже занято"}), 409

@app.route("/api/auth/login", methods=["POST"])
def login():
    d = request.json
    username = d.get("username","").strip()
    password = d.get("password","").strip()
    if not username or not password: return jsonify({"error":"Введи имя и пароль"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT id,username,password_hash,COALESCE(display_name,'') as display_name,
                          COALESCE(phone,'') as phone,COALESCE(bank,'') as bank,is_admin,is_banned
                          FROM users WHERE username=%s""", (username,))
            u = cur.fetchone()
    if not u or not check_password_hash(u['password_hash'], password):
        return jsonify({"error":"Неверное имя или пароль"}), 401
    if u['is_banned']: return jsonify({"error":"Аккаунт заблокирован"}), 403
    session.update({'user_id':str(u['id']),'username':u['username'],'display_name':u['display_name'],
                    'phone':u['phone'],'bank':u['bank'],'is_admin':bool(u['is_admin']),'login_time':time.time()})
    return jsonify({"ok":True,"username":u['username'],"display_name":u['display_name'],
                    "phone":u['phone'],"bank":u['bank'],"is_admin":bool(u['is_admin'])})

@app.route("/api/auth/logout", methods=["POST"])
def logout(): session.clear(); return jsonify({"ok":True})

@app.route("/api/auth/me")
def me():
    k = check_not_kicked()
    if k: return k
    if current_user_id():
        return jsonify({"user_id":current_user_id(),"username":session.get('username'),
                        "display_name":session.get('display_name',''),"phone":session.get('phone',''),
                        "bank":session.get('bank',''),"is_admin":session.get('is_admin',False)})
    return jsonify({"user_id":None}), 200

@app.route("/api/auth/profile", methods=["PUT"])
def update_profile():
    e = require_auth(); 
    if e: return e
    k = check_not_kicked()
    if k: return k
    d = request.json
    dn = d.get("display_name","").strip()
    ph = d.get("phone","").strip()
    bk = d.get("bank","").strip()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET display_name=%s,phone=%s,bank=%s WHERE id=%s", (dn,ph,bk,current_user_id()))
        conn.commit()
    session.update({'display_name':dn,'phone':ph,'bank':bk})
    return jsonify({"ok":True,"display_name":dn,"phone":ph,"bank":bk})

# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route("/api/admin/users")
def admin_users():
    e = require_admin()
    if e: return e
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT u.id,u.username,COALESCE(u.display_name,'') as display_name,
                          COALESCE(u.phone,'') as phone,COALESCE(u.bank,'') as bank,
                          u.is_admin,u.is_banned,u.created_at,u.session_invalidated_at,
                          COUNT(DISTINCT s.id) as session_count
                          FROM users u LEFT JOIN sessions s ON s.user_id=u.id
                          GROUP BY u.id ORDER BY u.created_at DESC""")
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/users/<uuid:uid>/ban", methods=["POST"])
def admin_ban(uid):
    e = require_admin()
    if e: return e
    if str(uid)==current_user_id(): return jsonify({"error":"Нельзя забанить себя"}), 400
    banned = request.json.get("banned", True)
    with get_conn() as conn:
        with conn.cursor() as cur: cur.execute("UPDATE users SET is_banned=%s WHERE id=%s",(banned,str(uid)))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/users/<uuid:uid>/kick", methods=["POST"])
def admin_kick(uid):
    e = require_admin()
    if e: return e
    if str(uid)==current_user_id(): return jsonify({"error":"Нельзя выбросить себя"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur: cur.execute("UPDATE users SET session_invalidated_at=NOW() WHERE id=%s",(str(uid),))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/users/<uuid:uid>/reset-password", methods=["POST"])
def admin_reset_password(uid):
    e = require_admin()
    if e: return e
    pw = request.json.get("password","").strip()
    if not pw or len(pw)<4: return jsonify({"error":"Пароль минимум 4 символа"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur: cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",(generate_password_hash(pw),str(uid)))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/admin/users/<uuid:uid>/toggle-admin", methods=["POST"])
def admin_toggle_admin(uid):
    e = require_admin()
    if e: return e
    if str(uid)==current_user_id(): return jsonify({"error":"Нельзя изменить свои права"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_admin=NOT is_admin WHERE id=%s RETURNING is_admin",(str(uid),))
            row = cur.fetchone()
        conn.commit()
    return jsonify({"ok":True,"is_admin":bool(row['is_admin'])})

@app.route("/api/admin/users/<uuid:uid>", methods=["DELETE"])
def admin_delete_user(uid):
    e = require_admin()
    if e: return e
    if str(uid)==current_user_id(): return jsonify({"error":"Нельзя удалить себя"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur: cur.execute("DELETE FROM users WHERE id=%s",(str(uid),))
        conn.commit()
    return jsonify({"ok":True})

# ── Upload ────────────────────────────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
def upload_image():
    e = require_auth()
    if e: return e
    k = check_not_kicked()
    if k: return k
    if 'file' not in request.files: return jsonify({"error":"Файл не найден"}), 400
    file = request.files['file']
    if not file.filename or not allowed_file(file.filename): return jsonify({"error":"Недопустимый файл"}), 400
    ext = file.filename.rsplit('.',1)[1].lower()
    fn = f"{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(UPLOAD_FOLDER, fn))
    return jsonify({"path":f"/static/uploads/{fn}"}), 201

# ── Sessions ──────────────────────────────────────────────────────────────────

@app.route("/api/sessions", methods=["POST"])
def create_session():
    e = require_auth()
    if e: return e
    k = check_not_kicked()
    if k: return k
    name = request.json.get("name","").strip() or "Новая сессия"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO sessions (name,user_id) VALUES (%s,%s) RETURNING id,name,created_at",(name,current_user_id()))
            row = cur.fetchone()
            cur.execute("INSERT INTO session_members (session_id,user_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",(str(row['id']),current_user_id()))
        conn.commit()
    return jsonify(dict(row)), 201

@app.route("/api/sessions")
def list_sessions():
    e = require_auth()
    if e: return e
    k = check_not_kicked()
    if k: return k
    limit = int(request.args.get("limit",20))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT s.id,s.name,s.created_at,COUNT(DISTINCT o.id) as order_count,
                          COALESCE(SUM(p.amount) FILTER (WHERE p.is_payer=TRUE),0) as total,
                          (s.user_id=%s) as is_owner
                          FROM sessions s
                          JOIN session_members sm ON sm.session_id=s.id AND sm.user_id=%s
                          LEFT JOIN orders o ON o.session_id=s.id
                          LEFT JOIN participants p ON p.order_id=o.id
                          GROUP BY s.id ORDER BY s.created_at DESC LIMIT %s""",
                         (current_user_id(),current_user_id(),limit))
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/sessions/<uuid:sid>")
def get_session(sid):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,created_at FROM sessions WHERE id=%s",(str(sid),))
            sr = cur.fetchone()
            if not sr: return jsonify({"error":"Сессия не найдена"}), 404
            cur.execute("""SELECT o.id,o.name,o.created_at,COALESCE(o.image_path,'') as image_path,o.items,
                          COALESCE(SUM(p.amount) FILTER (WHERE p.is_payer=TRUE),0) AS total
                          FROM orders o LEFT JOIN participants p ON p.order_id=o.id
                          WHERE o.session_id=%s GROUP BY o.id ORDER BY o.created_at""",(str(sid),))
            orders = cur.fetchall()
            cur.execute("UPDATE sessions SET updated_at=NOW() WHERE id=%s",(str(sid),))
            if current_user_id():
                cur.execute("INSERT INTO session_members (session_id,user_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",(str(sid),current_user_id()))
            result = []
            for o in orders:
                cur.execute("""SELECT id,name,amount,is_payer,COALESCE(phone,'') as phone,COALESCE(bank,'') as bank
                              FROM participants WHERE order_id=%s ORDER BY is_payer DESC,name""",(str(o["id"]),))
                result.append({**dict(o),"participants":[dict(p) for p in cur.fetchall()]})
        conn.commit()
    return jsonify({"session":dict(sr),"orders":result})

@app.route("/api/sessions/<uuid:sid>", methods=["DELETE"])
def delete_session(sid):
    e = require_auth()
    if e: return e
    with get_conn() as conn:
        with conn.cursor() as cur: cur.execute("DELETE FROM sessions WHERE id=%s AND user_id=%s",(str(sid),current_user_id()))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/sessions/<uuid:sid>/leave", methods=["POST"])
def leave_session(sid):
    e = require_auth()
    if e: return e
    with get_conn() as conn:
        with conn.cursor() as cur: cur.execute("DELETE FROM session_members WHERE session_id=%s AND user_id=%s",(str(sid),current_user_id()))
        conn.commit()
    return jsonify({"ok":True})

# ── Orders ────────────────────────────────────────────────────────────────────

@app.route("/api/sessions/<uuid:sid>/orders", methods=["POST"])
def create_order(sid):
    e = require_auth()
    if e: return e
    k = check_not_kicked()
    if k: return k
    d = request.json
    name = d.get("name","").strip()
    parts = d.get("participants",[])
    img = d.get("image_path","").strip()
    items = d.get("items", None)
    if not name or not parts: return jsonify({"error":"Заполни все поля"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO orders (session_id,name,image_path,items) VALUES (%s,%s,%s,%s) RETURNING id",
                        (str(sid),name,img,_json.dumps(items) if items is not None else None))
            oid = cur.fetchone()["id"]
            for i,p in enumerate(parts):
                pn=p.get("name","").strip(); pa=float(p.get("amount",0))
                if not pn or pa<=0: return jsonify({"error":"Проверь данные"}), 400
                cur.execute("INSERT INTO participants (order_id,name,amount,is_payer,phone,bank) VALUES (%s,%s,%s,%s,%s,%s)",
                            (str(oid),pn,pa,i==0,p.get("phone","").strip(),p.get("bank","").strip()))
            cur.execute("UPDATE sessions SET updated_at=NOW() WHERE id=%s",(str(sid),))
        conn.commit()
    return jsonify({"id":str(oid)}), 201

@app.route("/api/orders/<uuid:oid>", methods=["PUT"])
def update_order(oid):
    e = require_auth()
    if e: return e
    k = check_not_kicked()
    if k: return k
    d = request.json
    name=d.get("name","").strip(); parts=d.get("participants",[]); img=d.get("image_path","").strip()
    items=d.get("items", None)
    if not name or not parts: return jsonify({"error":"Заполни все поля"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE orders SET name=%s,image_path=%s,items=%s WHERE id=%s",
                        (name,img,_json.dumps(items) if items is not None else None,str(oid)))
            cur.execute("DELETE FROM participants WHERE order_id=%s",(str(oid),))
            for i,p in enumerate(parts):
                cur.execute("INSERT INTO participants (order_id,name,amount,is_payer,phone,bank) VALUES (%s,%s,%s,%s,%s,%s)",
                            (str(oid),p.get("name","").strip(),float(p.get("amount",0)),i==0,p.get("phone","").strip(),p.get("bank","").strip()))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/orders/<uuid:oid>", methods=["DELETE"])
def delete_order(oid):
    e = require_auth()
    if e: return e
    with get_conn() as conn:
        with conn.cursor() as cur: cur.execute("DELETE FROM orders WHERE id=%s",(str(oid),))
        conn.commit()
    return jsonify({"ok":True})

# ── Repayments ────────────────────────────────────────────────────────────────

@app.route("/api/sessions/<uuid:sid>/repay", methods=["POST"])
def repay(sid):
    d=request.json
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO repayments (session_id,debtor,creditor,amount) VALUES (%s,%s,%s,%s)",
                        (str(sid),d.get("debtor","").strip(),d.get("creditor","").strip(),float(d.get("amount",0))))
        conn.commit()
    return jsonify({"ok":True})

@app.route("/api/sessions/<uuid:sid>/repay", methods=["DELETE"])
def undo_repay(sid):
    d=request.json
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""DELETE FROM repayments WHERE id=(SELECT id FROM repayments
                WHERE session_id=%s AND debtor=%s AND creditor=%s ORDER BY created_at DESC LIMIT 1)""",
                (str(sid),d.get("debtor","").strip(),d.get("creditor","").strip()))
        conn.commit()
    return jsonify({"ok":True})

# ── Summary ───────────────────────────────────────────────────────────────────

@app.route("/api/sessions/<uuid:sid>/summary")
def get_summary(sid):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT p.name,p.amount,p.is_payer,o.id AS order_id FROM participants p JOIN orders o ON o.id=p.order_id WHERE o.session_id=%s",(str(sid),))
            rows=cur.fetchall()
            cur.execute("SELECT debtor,creditor,SUM(amount) as paid FROM repayments WHERE session_id=%s GROUP BY debtor,creditor",(str(sid),))
            rep=cur.fetchall()
    repaid={(r["debtor"],r["creditor"]):float(r["paid"]) for r in rep}
    om={}
    for r in rows:
        oid=str(r["order_id"])
        if oid not in om: om[oid]={"payer":None,"others_total":0.0}
        if r["is_payer"]: om[oid]["payer"]=r["name"]
        else: om[oid]["others_total"]+=float(r["amount"])
    grand=sum(float(r["amount"]) for r in rows if r["is_payer"])
    pt={}
    for r in rows: pt.setdefault(r["name"],0.0); pt[r["name"]]+=float(r["amount"])
    bal={n:0.0 for n in pt}
    for oid,o in om.items():
        if o["payer"]: bal[o["payer"]]+=o["others_total"]
        for r in rows:
            if str(r["order_id"])==oid and not r["is_payer"]: bal[r["name"]]-=float(r["amount"])
    creds=sorted([{"name":k,"val":v} for k,v in bal.items() if v>0.005],key=lambda x:-x["val"])
    debts=sorted([{"name":k,"val":-v} for k,v in bal.items() if v<-0.005],key=lambda x:-x["val"])
    txs,ci,di=[],0,0
    while ci<len(creds) and di<len(debts):
        c,d=creds[ci],debts[di]; amt=min(c["val"],d["val"])
        if amt>0.005:
            paid=repaid.get((d["name"],c["name"]),0.0); rem=round(max(amt-paid,0),2)
            txs.append({"from":d["name"],"to":c["name"],"amount":round(amt,2),"paid":round(min(paid,amt),2),"remaining":rem,"settled":rem<=0})
        c["val"]-=amt; d["val"]-=amt
        if c["val"]<0.005: ci+=1
        if d["val"]<0.005: di+=1
    return jsonify({"grand_total":round(grand,2),
                    "person_totals":[{"name":k,"amount":round(v,2)} for k,v in sorted(pt.items(),key=lambda x:-x[1])],
                    "transactions":txs})

# ── Stats ─────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def get_stats():
    uid=current_user_id()
    with get_conn() as conn:
        with conn.cursor() as cur:
            def q(sql, p=None): cur.execute(sql, p); return cur.fetchall()
            def q1(sql, p=None): cur.execute(sql, p); return cur.fetchone()
            sm_join="JOIN session_members sm ON sm.session_id=s.id AND sm.user_id=%s"
            top_payers=q(f"""SELECT p.name,SUM(ot.total) as paid_total,COUNT(DISTINCT o.id) as times
                FROM participants p JOIN orders o ON o.id=p.order_id JOIN sessions s ON s.id=o.session_id {sm_join if uid else ''}
                JOIN (SELECT order_id,SUM(amount) FILTER (WHERE is_payer=TRUE) as total FROM participants GROUP BY order_id) ot ON ot.order_id=o.id
                WHERE p.is_payer=TRUE GROUP BY p.name ORDER BY paid_total DESC LIMIT 5""", (uid,) if uid else None)
            top_debtors=q(f"""SELECT p.name,SUM(p.amount) as owed_total,COUNT(DISTINCT o.id) as times
                FROM participants p JOIN orders o ON o.id=p.order_id JOIN sessions s ON s.id=o.session_id {sm_join if uid else ''}
                WHERE p.is_payer=FALSE GROUP BY p.name ORDER BY owed_total DESC LIMIT 5""", (uid,) if uid else None)
            top_orders=q(f"""SELECT o.name,SUM(p.amount) FILTER (WHERE p.is_payer=TRUE) as total,s.name as session_name
                FROM orders o JOIN participants p ON p.order_id=o.id JOIN sessions s ON s.id=o.session_id {sm_join if uid else ''}
                GROUP BY o.id,s.name ORDER BY total DESC LIMIT 5""", (uid,) if uid else None)
            grand=q1(f"""SELECT COALESCE(SUM(p.amount) FILTER (WHERE p.is_payer=TRUE),0) as grand
                FROM participants p JOIN orders o ON o.id=p.order_id JOIN sessions s ON s.id=o.session_id {sm_join if uid else ''}""",
                (uid,) if uid else None)
            i_owe=[]
            if uid:
                dn=(q1("SELECT COALESCE(display_name,'') as display_name FROM users WHERE id=%s",(uid,)) or {}).get('display_name','')
                if dn:
                    for r in q("""SELECT p_payer.name as creditor,p_payer.phone as phone,p_payer.bank as bank,
                                s.name as session_name,s.id as session_id,p_me.amount as my_amount,COALESCE(r.paid,0) as paid
                                FROM participants p_me JOIN orders o ON o.id=p_me.order_id
                                JOIN sessions s ON s.id=o.session_id
                                JOIN session_members sm ON sm.session_id=s.id AND sm.user_id=%s
                                JOIN participants p_payer ON p_payer.order_id=o.id AND p_payer.is_payer=TRUE
                                LEFT JOIN (SELECT creditor,debtor,SUM(amount) as paid FROM repayments GROUP BY creditor,debtor) r
                                    ON r.debtor=p_me.name AND r.creditor=p_payer.name
                                WHERE p_me.is_payer=FALSE AND LOWER(p_me.name)=LOWER(%s)
                                ORDER BY s.created_at DESC""", (uid,dn)):
                        rem=round(max(float(r['my_amount'])-float(r['paid']),0),2)
                        if rem>0: i_owe.append({"creditor":r['creditor'],"phone":r['phone'] or '',
                            "bank":r['bank'] or '',"session_name":r['session_name'],
                            "session_id":str(r['session_id']),"amount":round(float(r['my_amount']),2),"remaining":rem})
    return jsonify({"top_payers":[dict(r) for r in top_payers],"top_debtors":[dict(r) for r in top_debtors],
                    "top_orders":[dict(r) for r in top_orders],"grand_total":float(grand["grand"]),"i_owe":i_owe})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
