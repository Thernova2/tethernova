'use strict';
require('dotenv').config();
const express=require('express'), helmet=require('helmet'), rateLimit=require('express-rate-limit'), bcrypt=require('bcryptjs'), jwt=require('jsonwebtoken'), Database=require('better-sqlite3'), path=require('path');
const app=express(); app.use(helmet({contentSecurityPolicy:false})); app.use(express.json({limit:'20kb'})); app.use(rateLimit({windowMs:15*60*1000,max:180}));
const db=new Database(process.env.DB_FILE||'tethernova.sqlite'); db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, balance REAL NOT NULL DEFAULT 0, withdrawal_address TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS deposits(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, txid TEXT UNIQUE NOT NULL, amount REAL NOT NULL, status TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS withdrawals(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, address TEXT NOT NULL, amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', payout_txid TEXT UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
try{db.exec('ALTER TABLE users ADD COLUMN withdrawal_address TEXT')}catch(e){if(!String(e).includes('duplicate column'))throw e}
try{db.exec('ALTER TABLE users ADD COLUMN investment_started_at TEXT')}catch(e){if(!String(e).includes('duplicate column'))throw e}
for(const [name,ddl] of Object.entries({investment_balance:'REAL NOT NULL DEFAULT 0',total_profit:'REAL NOT NULL DEFAULT 0',last_profit_at:'TEXT'})){
 try{db.exec(`ALTER TABLE users ADD COLUMN ${name} ${ddl}`)}catch(e){if(!String(e).includes('duplicate column'))throw e}
}
try{db.exec('ALTER TABLE withdrawals ADD COLUMN investment_deduction REAL NOT NULL DEFAULT 0')}catch(e){if(!String(e).includes('duplicate column'))throw e}

// Referral database structure only; no balance or payout integration.
for (const [name, ddl] of Object.entries({
  invite_code: 'TEXT',
  referred_by_user_id: 'INTEGER'
})) {
  try {
    db.exec(`ALTER TABLE users ADD COLUMN ${name} ${ddl}`);
  } catch (e) {
    if (!String(e).includes('duplicate column')) throw e;
  }
}

db.exec(`
  UPDATE users
  SET invite_code = lower(hex(randomblob(6)))
  WHERE invite_code IS NULL OR invite_code = '';

  CREATE UNIQUE INDEX IF NOT EXISTS idx_users_invite_code
  ON users(invite_code);

  CREATE INDEX IF NOT EXISTS idx_users_referred_by
  ON users(referred_by_user_id);

  CREATE TABLE IF NOT EXISTS referrals (
    id INTEGER PRIMARY KEY,
    referrer_user_id INTEGER NOT NULL REFERENCES users(id),
    referred_user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK(status IN ('pending', 'qualified')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    qualified_at TEXT,
    CHECK(referrer_user_id <> referred_user_id)
  );

  CREATE TABLE IF NOT EXISTS referral_points (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    referral_id INTEGER NOT NULL REFERENCES referrals(id),
    reward_type TEXT NOT NULL
      CHECK(reward_type IN ('invitee', 'referrer')),
    points INTEGER NOT NULL CHECK(points > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(referral_id, reward_type)
  );
`);


db.exec(`
  CREATE TABLE IF NOT EXISTS investment_rewards (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    related_user_id INTEGER REFERENCES users(id),
    reward_type TEXT NOT NULL CHECK(reward_type IN ('first_investment', 'referrer')),
    amount REAL NOT NULL CHECK(amount > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_reward_first_investment
    ON investment_rewards(user_id) WHERE reward_type='first_investment';
  CREATE UNIQUE INDEX IF NOT EXISTS idx_reward_referrer_invitee
    ON investment_rewards(related_user_id) WHERE reward_type='referrer';
`);

// Preserve accounts created by earlier builds: their existing balance becomes the initial compounding base.
db.prepare("UPDATE users SET investment_balance=balance WHERE investment_started_at IS NOT NULL AND investment_balance=0 AND total_profit=0").run();
db.prepare("UPDATE users SET last_profit_at=investment_started_at WHERE investment_started_at IS NOT NULL AND last_profit_at IS NULL").run();
const DAY_MS=24*60*60*1000, DAILY_RATE=0.02, MONEY_SCALE=1000000;
const money=n=>Math.round((Number(n)+Number.EPSILON)*MONEY_SCALE)/MONEY_SCALE;
function accrueUser(userId){
 const u=db.prepare('SELECT balance,investment_balance,total_profit,investment_started_at,last_profit_at FROM users WHERE id=?').get(userId);
 if(!u||!u.investment_started_at)return;
 let last=Date.parse(u.last_profit_at||u.investment_started_at);
 if(!Number.isFinite(last))last=Date.parse(u.investment_started_at);
 const days=Math.floor((Date.now()-last)/DAY_MS);
 if(days<1)return;
 const apply=db.transaction(()=>{
  let base=Number(u.investment_balance||0),balance=Number(u.balance||0),total=Number(u.total_profit||0);
  for(let i=0;i<days;i++){const profit=money(base*DAILY_RATE);base=money(base+profit);balance=money(balance+profit);total=money(total+profit);}
  const newLast=new Date(last+days*DAY_MS).toISOString();
  db.prepare('UPDATE users SET balance=?,investment_balance=?,total_profit=?,last_profit_at=? WHERE id=?').run(balance,base,total,newLast,userId);
 });
 apply();
}
const DEFAULT_ADDRESS=process.env.TRON_DEPOSIT_ADDRESS||'TMxstbh6PXqWCjVpyavwkyDjaLFmMxP2kn';
db.prepare('INSERT OR IGNORE INTO app_settings(key,value) VALUES(?,?)').run('tron_deposit_address',DEFAULT_ADDRESS);
const getDepositAddress=()=>db.prepare('SELECT value FROM app_settings WHERE key=?').get('tron_deposit_address')?.value||DEFAULT_ADDRESS;
const USDT='TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj';
const auth=(req,res,next)=>{
  try{
    const header=req.headers.authorization||'';
    if(!header.startsWith('Bearer '))return res.status(401).json({error:'Please log in first'});
    const t=header.slice(7).trim();
    if(!t)return res.status(401).json({error:'Please log in first'});
    const user=jwt.verify(t,process.env.JWT_SECRET);
    if(!Number.isInteger(user.id)||typeof user.email!=='string')return res.status(401).json({error:'Please log in first'});
    req.user=user;
    next();
  }catch{
    return res.status(401).json({error:'Please log in first'});
  }
};
const admin=(req,res,next)=>{
  const configured=String(process.env.ADMIN_EMAIL||'').trim().toLowerCase();
  if(!configured||String(req.user.email||'').toLowerCase()!==configured)return res.sendStatus(403);
  const current=db.prepare('SELECT email FROM users WHERE id=?').get(req.user.id);
  if(!current||current.email.toLowerCase()!==configured)return res.sendStatus(403);
  next();
};
const token=u=>jwt.sign({id:u.id,email:u.email},process.env.JWT_SECRET,{expiresIn:'7d'});
app.get('/api/config',(q,s)=>s.json({depositAddress:getDepositAddress(),network:'TRON / TRC20',activity:'sample'}));
app.post('/api/register',async(q,s)=>{
  const email=String(q.body.email||'').trim().toLowerCase();
  const pw=String(q.body.password||'');
  const inviteCode=String(q.body.inviteCode||'').trim().toLowerCase();
  if(!/^\S+@\S+\.\S+$/.test(email)||pw.length<10)
    return s.status(400).json({error:'Enter a valid email address and a password with at least 10 characters'});
  if(inviteCode&&!/^[a-f0-9]{12}$/.test(inviteCode))
    return s.status(400).json({error:'Invalid referral code'});
  const referrer=inviteCode?db.prepare('SELECT id FROM users WHERE invite_code=?').get(inviteCode):null;
  if(inviteCode&&!referrer)
    return s.status(400).json({error:'Referral code not found'});
  try{
    const password=await bcrypt.hash(pw,12);
    const create=db.transaction(()=>{
      const info=db.prepare('INSERT INTO users(email,password,invite_code) VALUES(?,?,lower(hex(randomblob(6))))').run(email,password);
      if(referrer){
        db.prepare('UPDATE users SET referred_by_user_id=? WHERE id=?').run(referrer.id,info.lastInsertRowid);
        db.prepare("INSERT INTO referrals(referrer_user_id,referred_user_id,status) VALUES(?,?,'pending')").run(referrer.id,info.lastInsertRowid);
      }
      return info.lastInsertRowid;
    });
    const id=create();
    const u=db.prepare('SELECT id,email,balance,withdrawal_address FROM users WHERE id=?').get(id);
    s.json({token:token(u),user:u});
  }catch(e){
    if(String(e).includes('UNIQUE'))return s.status(409).json({error:'This email address is already registered'});
    s.status(500).json({error:'Could not register this account'});
  }
});
app.get('/api/referrals',auth,(q,s)=>{
  const u=db.prepare('SELECT invite_code FROM users WHERE id=?').get(q.user.id);
  if(!u)return s.sendStatus(404);
  const count=db.prepare('SELECT COUNT(*) AS n FROM referrals WHERE referrer_user_id=?').get(q.user.id).n;
  s.json({inviteCode:u.invite_code,count});
});

const loginLimiter=rateLimit({
  windowMs:15*60*1000,
  max:5,
  standardHeaders:true,
  legacyHeaders:false,
  message:{error:'Too many login attempts. Try again in 15 minutes.'},
  skipSuccessfulRequests:true
});
app.post('/api/login',loginLimiter,async(q,s)=>{const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(q.body.email||'').trim().toLowerCase());if(!u||!await bcrypt.compare(String(q.body.password||''),u.password))return s.status(401).json({error:'Incorrect email address or password'});s.json({token:token(u),user:{id:u.id,email:u.email,balance:u.balance}})});
app.get('/api/me',auth,(q,s)=>{accrueUser(q.user.id);const u=db.prepare('SELECT id,email,balance,withdrawal_address,investment_started_at,investment_balance,total_profit,last_profit_at FROM users WHERE id=?').get(q.user.id);if(!u)return s.sendStatus(404);const elapsed=u.investment_started_at?Math.max(0,Date.now()-Date.parse(u.investment_started_at)):0;const daysElapsed=Math.floor(elapsed/DAY_MS);const unlocked=!!u.investment_started_at&&elapsed>=10*DAY_MS;s.json({user:u,investment:{dailyRate:DAILY_RATE,dailyProfit:money(Number(u.investment_balance||0)*DAILY_RATE),daysElapsed,daysRemaining:Math.max(0,10-daysElapsed),withdrawalUnlocked:unlocked,availableToWithdraw:unlocked?Number(u.balance):0},isAdmin:u.email.toLowerCase()===String(process.env.ADMIN_EMAIL||'').toLowerCase(),deposits:db.prepare('SELECT txid,amount,status,created_at FROM deposits WHERE user_id=? ORDER BY id DESC').all(u.id),withdrawals:db.prepare('SELECT address,amount,status,payout_txid,created_at FROM withdrawals WHERE user_id=? ORDER BY id DESC').all(u.id)})});
app.get('/api/investment/status',auth,(q,s)=>{
  accrueUser(q.user.id);
  const u=db.prepare('SELECT balance,investment_started_at,investment_balance,total_profit FROM users WHERE id=?').get(q.user.id);
  if(!u)return s.sendStatus(404);
  const credited=db.prepare("SELECT COUNT(*) AS n FROM deposits WHERE user_id=? AND status='credited'").get(q.user.id).n;
  const started=!!u.investment_started_at;
  const eligible=!!credited&&Number(u.balance)>0;
  const elapsed=started?Math.max(0,Date.now()-Date.parse(u.investment_started_at)):0;
  const unlocked=started&&elapsed>=10*DAY_MS;
  const unlockAt=started?Date.parse(u.investment_started_at)+10*DAY_MS:0;
  s.json({
    eligible,started,unlocked,unlockAt,
    serverNow:Date.now(),
    todayProfit:money(Number(u.investment_balance||0)*DAILY_RATE),
    totalProfit:Number(u.total_profit||0)
  });
});
// Investment timer is account-level and starts only after a credited deposit and an explicit user action.
// Investment starts after a credited deposit and explicit user action.
app.post('/api/investment/start',auth,(q,s)=>{
  const startedAt=new Date().toISOString();
  try {
    const result=db.transaction(()=>{
      const u=db.prepare('SELECT balance,investment_started_at,referred_by_user_id FROM users WHERE id=?').get(q.user.id);
      if(!u)throw new Error('MISSING');
      if(u.investment_started_at)throw new Error('ALREADY_STARTED');

      const credited=db.prepare("SELECT COUNT(*) AS n FROM deposits WHERE user_id=? AND status='credited'").get(q.user.id).n;
      if(!credited||Number(u.balance)<=0)throw new Error('NOT_ELIGIBLE');

      const reward=db.prepare("INSERT OR IGNORE INTO investment_rewards(user_id,reward_type,amount) VALUES(?,'first_investment',3)").run(q.user.id);
      const bonus=reward.changes?3:0;

      db.prepare('UPDATE users SET balance=balance+?,investment_started_at=?,last_profit_at=?,investment_balance=balance+?,total_profit=0 WHERE id=? AND investment_started_at IS NULL').run(bonus,startedAt,startedAt,bonus,q.user.id);

      if(u.referred_by_user_id){
        const ref=db.prepare("SELECT id,referrer_user_id FROM referrals WHERE referred_user_id=? AND status IN ('pending','qualified')").get(q.user.id);
        if(ref){
          const paid=db.prepare("INSERT OR IGNORE INTO investment_rewards(user_id,related_user_id,reward_type,amount) VALUES(?,?,'referrer',5)").run(ref.referrer_user_id,q.user.id);
          if(paid.changes){
            db.prepare('UPDATE users SET balance=balance+?,investment_balance=CASE WHEN investment_started_at IS NOT NULL THEN investment_balance+? ELSE investment_balance END WHERE id=?').run(5,5,ref.referrer_user_id);
          }
          db.prepare("INSERT OR IGNORE INTO referral_points(user_id,referral_id,reward_type,points) VALUES(?,?,'referrer',500)").run(ref.referrer_user_id,ref.id);
          db.prepare("INSERT OR IGNORE INTO referral_points(user_id,referral_id,reward_type,points) VALUES(?,?,'invitee',300)").run(q.user.id,ref.id);
          db.prepare("UPDATE referrals SET status='qualified',qualified_at=COALESCE(qualified_at,CURRENT_TIMESTAMP) WHERE id=?").run(ref.id);
        }
      }
      return {firstInvestmentBonus:bonus};
    })();
    s.json({ok:true,startedAt,dailyRate:DAILY_RATE,rewards:result});
  } catch(e) {
    if(e.message==='MISSING')return s.sendStatus(404);
    if(e.message==='ALREADY_STARTED')return s.status(409).json({error:'The investment period has already started'});
    if(e.message==='NOT_ELIGIBLE')return s.status(403).json({error:'Your deposit must first be approved by the operator and credited to your account.'});
    console.error(e);
    s.status(500).json({error:'Could not start the investment period'});
  }
});
// User submits a TXID and claimed amount. No automatic crediting or chain watcher: admin verifies on TronScan manually.
app.post('/api/deposit/claim',auth,(q,s)=>{const txid=String(q.body.txid||'').trim(),amount=Number(q.body.amount);if(!/^[a-fA-F0-9]{64}$/.test(txid)||!Number.isFinite(amount)||amount<=0||amount>10000000)return s.status(400).json({error:'Enter a valid TXID and amount'});try{db.prepare('INSERT INTO deposits(user_id,txid,amount,status) VALUES(?,?,?,?)').run(q.user.id,txid,amount,'pending_review');s.json({message:'Deposit request submitted. Your balance will be credited after manual review by the administrator.'})}catch(e){if(String(e).includes('UNIQUE'))return s.status(409).json({error:'This TXID has already been submitted'});s.status(500).json({error:'Could not submit the deposit request'})}});
app.post('/api/withdrawal-address',auth,(q,s)=>{const address=String(q.body.address||'').trim();if(!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address))return s.status(400).json({error:'Enter a valid TRON address'});db.prepare('UPDATE users SET withdrawal_address=? WHERE id=?').run(address,q.user.id);s.json({ok:true})});
app.post('/api/withdrawals',auth,(q,s)=>{accrueUser(q.user.id);const address=String(q.body.address||'').trim(),amount=Number(q.body.amount);if(!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address)||!Number.isFinite(amount)||amount<20)return s.status(400).json({error:'Enter a valid TRON address and an amount of at least 20 USDT'});const tx=db.transaction(()=>{const u=db.prepare('SELECT balance,investment_balance,investment_started_at FROM users WHERE id=?').get(q.user.id);if(!u)throw new Error('MISSING');if(!u.investment_started_at||Date.now()-Date.parse(u.investment_started_at)<10*DAY_MS)throw new Error('LOCKED');if(amount>u.balance)throw new Error('INSUFFICIENT');db.prepare('UPDATE users SET balance=balance-?,investment_balance=MAX(0,investment_balance-?),withdrawal_address=? WHERE id=?').run(amount,amount,address,q.user.id);db.prepare('INSERT INTO withdrawals(user_id,address,amount,investment_deduction,status) VALUES(?,?,?,?,?)').run(q.user.id,address,amount,amount,'pending_manual');});try{tx();s.json({message:'Withdrawal request submitted. The administrator will process the transfer manually.'})}catch(e){if(e.message==='LOCKED')return s.status(403).json({error:'Withdrawals unlock after 10 complete days from the investment start time.'});if(e.message==='INSUFFICIENT')return s.status(400).json({error:'Insufficient balance'});s.status(500).json({error:'Could not submit the withdrawal request'})}});
app.post('/api/admin/deposit-address',auth,admin,(q,s)=>{const address=String(q.body.address||'').trim();if(!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address))return s.status(400).json({error:'Enter a valid 34-character TRON address beginning with T.'});db.prepare('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run('tron_deposit_address',address);s.json({ok:true,depositAddress:address,message:'Shared deposit address updated for all users.'})});
app.get('/api/admin/queue',auth,admin,(q,s)=>s.json({deposits:db.prepare("SELECT d.*,u.email FROM deposits d JOIN users u ON u.id=d.user_id WHERE d.status='pending_review'").all(),withdrawals:db.prepare("SELECT w.*,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.status='pending_manual'").all()}));
app.post('/api/admin/deposits/:id/approve',auth,admin,(q,s)=>{const amount=Number(q.body.amount);if(!Number.isFinite(amount)||amount<=0||amount>10000000)return s.status(400).json({error:'The approved amount is invalid'});const d=db.prepare("SELECT * FROM deposits WHERE id=? AND status='pending_review'").get(q.params.id);if(!d)return s.sendStatus(404);db.transaction(()=>{db.prepare("UPDATE deposits SET amount=?,status='credited' WHERE id=? AND status='pending_review'").run(amount,d.id);db.prepare('UPDATE users SET balance=balance+?,investment_balance=CASE WHEN investment_started_at IS NOT NULL THEN investment_balance+? ELSE investment_balance END WHERE id=?').run(amount,amount,d.user_id)})();s.json({ok:true})});
app.post('/api/admin/deposits/:id/reject',auth,admin,(q,s)=>{const r=db.prepare("UPDATE deposits SET status='rejected' WHERE id=? AND status='pending_review'").run(q.params.id);s.json({ok:r.changes===1})});
app.post('/api/admin/withdrawals/:id/paid',auth,admin,(q,s)=>{const txid=String(q.body.txid||'').trim();if(!/^[a-fA-F0-9]{64}$/.test(txid))return s.status(400).json({error:'The payout TXID is invalid'});try{const r=db.prepare("UPDATE withdrawals SET status='paid_manual',payout_txid=? WHERE id=? AND status='pending_manual'").run(txid,q.params.id);s.json({ok:r.changes===1})}catch(e){if(String(e).includes('UNIQUE'))return s.status(409).json({error:'This TXID has already been used for another withdrawal'});s.status(500).json({error:'Could not record the TXID'})}});
app.post('/api/admin/withdrawals/:id/reject',auth,admin,(q,s)=>{const w=db.prepare("SELECT * FROM withdrawals WHERE id=? AND status='pending_manual'").get(q.params.id);if(!w)return s.sendStatus(404);db.transaction(()=>{db.prepare("UPDATE withdrawals SET status='rejected' WHERE id=?").run(w.id);db.prepare('UPDATE users SET balance=balance+?,investment_balance=investment_balance+? WHERE id=?').run(w.amount,Number(w.investment_deduction||w.amount),w.user_id)})();s.json({ok:true})});
app.use(express.static(path.join(__dirname,'public')));app.get('*',(q,s)=>s.sendFile(path.join(__dirname,'public','index.html')));
if(!process.env.JWT_SECRET||process.env.JWT_SECRET.length<32){console.error('Set a random JWT_SECRET of at least 32 characters');process.exit(1)}
app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('TetherNova listening on port '+(process.env.PORT||3000)));
