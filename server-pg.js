'use strict';
require('dotenv').config();

const express=require('express');
const helmet=require('helmet');
const rateLimit=require('express-rate-limit');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const path=require('path');
const crypto=require('crypto');
const {pool,query,transaction}=require('./pg-db');

const app=express();
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'20kb'}));
app.use(rateLimit({windowMs:15*60*1000,max:180}));

const DAY_MS=86400000;
const DAILY_RATE=0.02;
const MONEY_SCALE=1000000;
const money=n=>Math.round((Number(n)+Number.EPSILON)*MONEY_SCALE)/MONEY_SCALE;
const DEFAULT_ADDRESS=process.env.TRON_DEPOSIT_ADDRESS||'TMxstbh6PXqWCjVpyavwkyDjaLFmMxP2kn';
const USDT='TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj';

if(!process.env.JWT_SECRET||process.env.JWT_SECRET.length<32){
 console.error('JWT_SECRET must be at least 32 characters');
 process.exit(1);
}

const asyncRoute=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
const token=u=>jwt.sign({id:Number(u.id),email:u.email},process.env.JWT_SECRET,{expiresIn:'7d'});

async function accrueUser(userId){
 await transaction(async c=>{
  const r=await c.query(
   `SELECT balance,investment_balance,total_profit,
    investment_started_at,last_profit_at
    FROM users WHERE id=$1 FOR UPDATE`,[userId]);
  const u=r.rows[0];
  if(!u||!u.investment_started_at)return;
  let last=Date.parse(u.last_profit_at||u.investment_started_at);
  if(!Number.isFinite(last))last=Date.parse(u.investment_started_at);
  const days=Math.floor((Date.now()-last)/DAY_MS);
  if(days<1)return;
  let base=Number(u.investment_balance||0);
  let balance=Number(u.balance||0);
  let total=Number(u.total_profit||0);
  for(let i=0;i<days;i++){
   const profit=money(base*DAILY_RATE);
   base=money(base+profit);
   balance=money(balance+profit);
   total=money(total+profit);
  }
  const newLast=new Date(last+days*DAY_MS).toISOString();
  await c.query(
   `UPDATE users SET balance=$1,investment_balance=$2,
    total_profit=$3,last_profit_at=$4 WHERE id=$5`,
   [balance,base,total,newLast,userId]);
 });
}

async function getDepositAddress(){
 const r=await query("SELECT value FROM app_settings WHERE key=$1",['tron_deposit_address']);
 return r.rows[0]?.value||DEFAULT_ADDRESS;
}

async function auth(req,res,next){
 try{
  const h=req.headers.authorization||'';
  if(!h.startsWith('Bearer '))return res.status(401).json({error:'Please log in first'});
  const u=jwt.verify(h.slice(7).trim(),process.env.JWT_SECRET);
  if(!Number.isInteger(u.id)||typeof u.email!=='string')return res.status(401).json({error:'Please log in first'});
  req.user=u;
  next();
 }catch{return res.status(401).json({error:'Please log in first'});}
}

async function admin(req,res,next){
 try{
  const configured=String(process.env.ADMIN_EMAIL||'').trim().toLowerCase();
  if(!configured||String(req.user.email||'').toLowerCase()!==configured)return res.sendStatus(403);
  const r=await query('SELECT email FROM users WHERE id=$1',[req.user.id]);
  if(!r.rows[0]||r.rows[0].email.toLowerCase()!==configured)return res.sendStatus(403);
  next();
 }catch(e){next(e);}
}

app.get('/api/config',asyncRoute(async(q,s)=>{
 s.json({depositAddress:await getDepositAddress(),network:'TRON / TRC20',activity:'sample'});
}));

app.post('/api/register',asyncRoute(async(q,s)=>{
 const email=String(q.body.email||'').trim().toLowerCase();
 const pw=String(q.body.password||'');
 const inviteCode=String(q.body.inviteCode||'').trim().toLowerCase();
 if(!/^\S+@\S+\.\S+$/.test(email)||pw.length<10)
  return s.status(400).json({error:'Enter a valid email address and a password with at least 10 characters'});
 if(inviteCode&&!/^[a-f0-9]{12}$/.test(inviteCode))
  return s.status(400).json({error:'Invalid referral code'});
 const password=await bcrypt.hash(pw,12);
 try{
  const created=await transaction(async c=>{
   let referrer=null;
   if(inviteCode){
    const rr=await c.query('SELECT id FROM users WHERE invite_code=$1',[inviteCode]);
    referrer=rr.rows[0];
    if(!referrer)throw new Error('REFERRAL_NOT_FOUND');
   }
   const code=crypto.randomBytes(6).toString('hex');
   const r=await c.query(
    `INSERT INTO users(email,password,invite_code,referred_by_user_id)
     VALUES($1,$2,$3,$4) RETURNING id,email,balance,withdrawal_address`,
    [email,password,code,referrer?referrer.id:null]);
   const u=r.rows[0];
   if(referrer){
    await c.query(
     "INSERT INTO referrals(referrer_user_id,referred_user_id,status) VALUES($1,$2,'pending')",
     [referrer.id,u.id]);
   }
   return u;
  });
  s.json({token:token(created),user:created});
 }catch(e){
  if(e.message==='REFERRAL_NOT_FOUND')return s.status(400).json({error:'Referral code not found'});
  if(e.code==='23505')return s.status(409).json({error:'This email address is already registered'});
  throw e;
 }
}));

app.get('/api/referrals',auth,asyncRoute(async(q,s)=>{
 const r=await query(
  `SELECT u.invite_code,
   (SELECT COUNT(*) FROM referrals f WHERE f.referrer_user_id=u.id) AS count
   FROM users u WHERE u.id=$1`,[q.user.id]);
 if(!r.rows[0])return s.sendStatus(404);
 s.json({inviteCode:r.rows[0].invite_code,count:Number(r.rows[0].count)});
}));

const loginLimiter=rateLimit({
 windowMs:15*60*1000,max:5,standardHeaders:true,
 legacyHeaders:false,
 message:{error:'Too many login attempts. Try again in 15 minutes.'},
 skipSuccessfulRequests:true
});

app.post('/api/login',loginLimiter,asyncRoute(async(q,s)=>{
 const r=await query('SELECT * FROM users WHERE email=$1',[String(q.body.email||'').trim().toLowerCase()]);
 const u=r.rows[0];
 if(!u||!await bcrypt.compare(String(q.body.password||''),u.password))
  return s.status(401).json({error:'Incorrect email address or password'});
 s.json({token:token(u),user:{id:Number(u.id),email:u.email,balance:Number(u.balance)}});
}));

app.get('/api/me',auth,asyncRoute(async(q,s)=>{
 await accrueUser(q.user.id);
 const r=await query(
  `SELECT id,email,balance,withdrawal_address,investment_started_at,
   investment_balance,total_profit,last_profit_at FROM users WHERE id=$1`,
  [q.user.id]);
 const u=r.rows[0];
 if(!u)return s.sendStatus(404);
 const elapsed=u.investment_started_at?Math.max(0,Date.now()-Date.parse(u.investment_started_at)):0;
 const daysElapsed=Math.floor(elapsed/DAY_MS);
 const unlocked=!!u.investment_started_at&&elapsed>=10*DAY_MS;
 const [d,w]=await Promise.all([
  query('SELECT txid,amount,status,created_at FROM deposits WHERE user_id=$1 ORDER BY id DESC',[u.id]),
  query('SELECT address,amount,status,payout_txid,created_at FROM withdrawals WHERE user_id=$1 ORDER BY id DESC',[u.id])
 ]);
 s.json({
  user:u,
  investment:{
   dailyRate:DAILY_RATE,
   dailyProfit:money(Number(u.investment_balance||0)*DAILY_RATE),
   daysElapsed,daysRemaining:Math.max(0,10-daysElapsed),
   withdrawalUnlocked:unlocked,availableToWithdraw:unlocked?Number(u.balance):0
  },
  isAdmin:u.email.toLowerCase()===String(process.env.ADMIN_EMAIL||'').toLowerCase(),
  deposits:d.rows,withdrawals:w.rows
 });
}));

app.get('/api/investment/status',auth,asyncRoute(async(q,s)=>{
 await accrueUser(q.user.id);
 const [ur,dr]=await Promise.all([
  query('SELECT balance,investment_started_at,investment_balance,total_profit FROM users WHERE id=$1',[q.user.id]),
  query("SELECT COUNT(*) AS n FROM deposits WHERE user_id=$1 AND status='credited'",[q.user.id])
 ]);
 const u=ur.rows[0];
 if(!u)return s.sendStatus(404);
 const started=!!u.investment_started_at;
 const elapsed=started?Math.max(0,Date.now()-Date.parse(u.investment_started_at)):0;
 s.json({
  eligible:Number(dr.rows[0].n)>0&&Number(u.balance)>0,
  started,unlocked:started&&elapsed>=10*DAY_MS,
  unlockAt:started?Date.parse(u.investment_started_at)+10*DAY_MS:0,
  serverNow:Date.now(),
  todayProfit:money(Number(u.investment_balance||0)*DAILY_RATE),
  totalProfit:Number(u.total_profit||0)
 });
}));

app.post('/api/investment/start',auth,asyncRoute(async(q,s)=>{
 const startedAt=new Date().toISOString();
 try{
  const result=await transaction(async c=>{
   const ur=await c.query(
    'SELECT balance,investment_started_at,referred_by_user_id FROM users WHERE id=$1 FOR UPDATE',
    [q.user.id]);
   const u=ur.rows[0];
   if(!u)throw new Error('MISSING');
   if(u.investment_started_at)throw new Error('ALREADY_STARTED');
   const dr=await c.query(
    "SELECT COUNT(*) AS n FROM deposits WHERE user_id=$1 AND status='credited'",
    [q.user.id]);
   if(Number(dr.rows[0].n)<1||Number(u.balance)<=0)throw new Error('NOT_ELIGIBLE');

   const reward=await c.query(
    `INSERT INTO investment_rewards(user_id,reward_type,amount)
     VALUES($1,'first_investment',3)
     ON CONFLICT (user_id) WHERE reward_type='first_investment'
     DO NOTHING RETURNING id`,[q.user.id]);
   const bonus=reward.rowCount?3:0;
   await c.query(
    `UPDATE users SET balance=balance+$1,investment_started_at=$2,
     last_profit_at=$2,investment_balance=balance+$1,total_profit=0
     WHERE id=$3 AND investment_started_at IS NULL`,
    [bonus,startedAt,q.user.id]);

   if(u.referred_by_user_id){
    const rr=await c.query(
     `SELECT id,referrer_user_id FROM referrals
      WHERE referred_user_id=$1 AND status IN ('pending','qualified') FOR UPDATE`,
     [q.user.id]);
    const ref=rr.rows[0];
    if(ref){
     const paid=await c.query(
      `INSERT INTO investment_rewards(user_id,related_user_id,reward_type,amount)
       VALUES($1,$2,'referrer',5)
       ON CONFLICT (related_user_id) WHERE reward_type='referrer'
       DO NOTHING RETURNING id`,
      [ref.referrer_user_id,q.user.id]);
     if(paid.rowCount){
      await c.query(
       `UPDATE users SET balance=balance+5,
        investment_balance=CASE WHEN investment_started_at IS NOT NULL
        THEN investment_balance+5 ELSE investment_balance END WHERE id=$1`,
       [ref.referrer_user_id]);
     }
     await c.query(
      `INSERT INTO referral_points(user_id,referral_id,reward_type,points)
       VALUES($1,$2,'referrer',500) ON CONFLICT DO NOTHING`,
      [ref.referrer_user_id,ref.id]);
     await c.query(
      `INSERT INTO referral_points(user_id,referral_id,reward_type,points)
       VALUES($1,$2,'invitee',300) ON CONFLICT DO NOTHING`,
      [q.user.id,ref.id]);
     await c.query(
      "UPDATE referrals SET status='qualified',qualified_at=COALESCE(qualified_at,CURRENT_TIMESTAMP::text) WHERE id=$1",
      [ref.id]);
    }
   }
   return {firstInvestmentBonus:bonus};
  });
  s.json({ok:true,startedAt,dailyRate:DAILY_RATE,rewards:result});
 }catch(e){
  if(e.message==='MISSING')return s.sendStatus(404);
  if(e.message==='ALREADY_STARTED')return s.status(409).json({error:'The investment period has already started'});
  if(e.message==='NOT_ELIGIBLE')return s.status(403).json({error:'Your deposit must first be approved by the operator and credited to your account.'});
  throw e;
 }
}));

app.post('/api/deposit/claim',auth,asyncRoute(async(q,s)=>{
 const txid=String(q.body.txid||'').trim(),amount=Number(q.body.amount);
 if(!/^[a-fA-F0-9]{64}$/.test(txid)||!Number.isFinite(amount)||amount<=0||amount>10000000)
  return s.status(400).json({error:'Enter a valid TXID and amount'});
 try{
  await query(
   "INSERT INTO deposits(user_id,txid,amount,status) VALUES($1,$2,$3,'pending_review')",
   [q.user.id,txid,amount]);
  s.json({message:'Deposit request submitted. Your balance will be credited after manual review by the administrator.'});
 }catch(e){
  if(e.code==='23505')return s.status(409).json({error:'This TXID has already been submitted'});
  throw e;
 }
}));

app.post('/api/withdrawal-address',auth,asyncRoute(async(q,s)=>{
 const address=String(q.body.address||'').trim();
 if(!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address))
  return s.status(400).json({error:'Enter a valid TRON address'});
 await query('UPDATE users SET withdrawal_address=$1 WHERE id=$2',[address,q.user.id]);
 s.json({ok:true});
}));

app.post('/api/withdrawals',auth,asyncRoute(async(q,s)=>{
 await accrueUser(q.user.id);
 const address=String(q.body.address||'').trim(),amount=Number(q.body.amount);
 if(!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address)||!Number.isFinite(amount)||amount<20)
  return s.status(400).json({error:'Enter a valid TRON address and an amount of at least 20 USDT'});
 try{
  await transaction(async c=>{
   const r=await c.query(
    'SELECT balance,investment_balance,investment_started_at FROM users WHERE id=$1 FOR UPDATE',
    [q.user.id]);
   const u=r.rows[0];
   if(!u)throw new Error('MISSING');
   if(!u.investment_started_at||Date.now()-Date.parse(u.investment_started_at)<10*DAY_MS)
    throw new Error('LOCKED');
   if(amount>Number(u.balance))throw new Error('INSUFFICIENT');
   const investmentDeduction=Math.min(amount,Number(u.investment_balance||0));
    await c.query(
     `UPDATE users SET balance=balance-$1,
      investment_balance=GREATEST(0,investment_balance-$4),
      withdrawal_address=$2 WHERE id=$3`,
     [amount,address,q.user.id,investmentDeduction]);
    await c.query(
     `INSERT INTO withdrawals(user_id,address,amount,investment_deduction,status)
      VALUES($1,$2,$3,$4,'pending_manual')`,
     [q.user.id,address,amount,investmentDeduction]);
  });
  s.json({message:'Withdrawal request submitted. The administrator will process the transfer manually.'});
 }catch(e){
  if(e.message==='LOCKED')return s.status(403).json({error:'Withdrawals unlock after 10 complete days from the investment start time.'});
  if(e.message==='INSUFFICIENT')return s.status(400).json({error:'Insufficient balance'});
  if(e.message==='MISSING')return s.sendStatus(404);
  throw e;
 }
}));

app.post('/api/admin/deposit-address',auth,admin,asyncRoute(async(q,s)=>{
 const address=String(q.body.address||'').trim();
 if(!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address))
  return s.status(400).json({error:'Enter a valid 34-character TRON address beginning with T.'});
 await query(
  `INSERT INTO app_settings(key,value) VALUES($1,$2)
   ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,
  ['tron_deposit_address',address]);
 s.json({ok:true,depositAddress:address,message:'Shared deposit address updated for all users.'});
}));

app.get('/api/admin/queue',auth,admin,asyncRoute(async(q,s)=>{
 const [d,w]=await Promise.all([
  query("SELECT d.*,u.email FROM deposits d JOIN users u ON u.id=d.user_id WHERE d.status='pending_review'"),
  query("SELECT w.*,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.status='pending_manual'")
 ]);
 s.json({deposits:d.rows,withdrawals:w.rows});
}));

app.post('/api/admin/deposits/:id/approve',auth,admin,asyncRoute(async(q,s)=>{
 const amount=Number(q.body.amount);
 if(!Number.isFinite(amount)||amount<=0||amount>10000000)
  return s.status(400).json({error:'The approved amount is invalid'});
 const done=await transaction(async c=>{
  const r=await c.query(
   "UPDATE deposits SET amount=$1,status='credited' WHERE id=$2 AND status='pending_review' RETURNING user_id",
   [amount,q.params.id]);
  if(!r.rowCount)return false;
  await c.query(
   `UPDATE users SET balance=balance+$1,
    investment_balance=CASE WHEN investment_started_at IS NOT NULL
    THEN investment_balance+$1 ELSE investment_balance END WHERE id=$2`,
   [amount,r.rows[0].user_id]);
  return true;
 });
 if(!done)return s.sendStatus(404);
 s.json({ok:true});
}));

app.post('/api/admin/deposits/:id/reject',auth,admin,asyncRoute(async(q,s)=>{
 const r=await query(
  "UPDATE deposits SET status='rejected' WHERE id=$1 AND status='pending_review' RETURNING id",
  [q.params.id]);
 s.json({ok:r.rowCount===1});
}));

app.post('/api/admin/withdrawals/:id/paid',auth,admin,asyncRoute(async(q,s)=>{
 const txid=String(q.body.txid||'').trim();
 if(!/^[a-fA-F0-9]{64}$/.test(txid))
  return s.status(400).json({error:'The payout TXID is invalid'});
 try{
  const r=await query(
   "UPDATE withdrawals SET status='paid_manual',payout_txid=$1 WHERE id=$2 AND status='pending_manual' RETURNING id",
   [txid,q.params.id]);
  s.json({ok:r.rowCount===1});
 }catch(e){
  if(e.code==='23505')return s.status(409).json({error:'This TXID has already been used for another withdrawal'});
  throw e;
 }
}));

app.post('/api/admin/withdrawals/:id/reject',auth,admin,asyncRoute(async(q,s)=>{
 const done=await transaction(async c=>{
  const r=await c.query(
   "SELECT * FROM withdrawals WHERE id=$1 AND status='pending_manual' FOR UPDATE",
   [q.params.id]);
  const w=r.rows[0];
  if(!w)return false;
  await c.query("UPDATE withdrawals SET status='rejected' WHERE id=$1",[w.id]);
  await c.query(
   'UPDATE users SET balance=balance+$1,investment_balance=investment_balance+$2 WHERE id=$3',
   [w.amount,(w.investment_deduction==null?Number(w.amount):Number(w.investment_deduction)),w.user_id]);
  return true;
 });
 if(!done)return s.sendStatus(404);
 s.json({ok:true});
}));

app.use(express.static(path.join(__dirname,'public')));
app.get('*',(q,s)=>s.sendFile(path.join(__dirname,'public','index.html')));
app.use((e,q,s,n)=>{
 console.error('SERVER ERROR:',e.message);
 if(!s.headersSent)s.status(500).json({error:'Internal server error'});
});

(async()=>{
 try{
  await query('SELECT 1');
  await query(
   `INSERT INTO app_settings(key,value) VALUES($1,$2)
    ON CONFLICT(key) DO NOTHING`,
   ['tron_deposit_address',DEFAULT_ADDRESS]);
  const port=Number(process.env.PORT||3001);
  app.listen(port,'0.0.0.0',()=>console.log('TetherNova PostgreSQL test server listening on port '+port));
 }catch(e){
  console.error('PostgreSQL startup failed:',e.message);
  process.exit(1);
 }
})();
