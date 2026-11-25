import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';
const { Pool } = pg;
const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized:false } : false });
app.use(helmet({ contentSecurityPolicy:false }));
app.use(express.json({limit:'1mb'}));
const schema='public', table='reclamante';
function auth(req,res,next){ const h=req.headers.authorization||''; try { req.user=jwt.verify(h.replace('Bearer ',''),process.env.JWT_SECRET); next(); } catch { res.status(401).json({error:'Não autorizado'}); } }
async function columns(){ const r=await pool.query(`SELECT column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 ORDER BY ordinal_position`,[schema,table]); return r.rows; }
function q(s){ return '"'+String(s).replaceAll('"','""')+'"'; }
app.post('/api/login', async (req,res)=>{ const {user,password}=req.body||{}; const okUser=user===process.env.ADMIN_USER; const okPass=process.env.ADMIN_PASSWORD_HASH ? await bcrypt.compare(password||'',process.env.ADMIN_PASSWORD_HASH) : password===process.env.ADMIN_PASSWORD; if(!okUser||!okPass) return res.status(401).json({error:'Credenciais inválidas'}); res.json({token:jwt.sign({user},process.env.JWT_SECRET,{expiresIn:'8h'})}); });
app.get('/api/meta',auth,async(req,res)=>{ try{res.json({schema,table,columns:await columns()});}catch(e){res.status(500).json({error:'Falha ao ler a estrutura da tabela'});} });
app.get('/api/records',auth,async(req,res)=>{ try{const cols=await columns(); const names=cols.map(x=>q(x.column_name)).join(','); const limit=Math.min(Number(req.query.limit)||50,200); const r=await pool.query(`SELECT ${names} FROM ${q(schema)}.${q(table)} ORDER BY 1 DESC LIMIT $1`,[limit]); res.json(r.rows);}catch(e){res.status(500).json({error:'Falha ao consultar registros'});} });
app.post('/api/records',auth,async(req,res)=>{ try{const cols=await columns(); const allowed=cols.filter(c=>!c.column_default && !['created_at','updated_at','id'].includes(c.column_name)).map(c=>c.column_name).filter(k=>Object.hasOwn(req.body,k)&&req.body[k]!==''&&req.body[k]!==null); if(!allowed.length) return res.status(400).json({error:'Nenhum campo informado'}); const vals=allowed.map(k=>req.body[k]); const r=await pool.query(`INSERT INTO ${q(schema)}.${q(table)} (${allowed.map(q).join(',')}) VALUES (${vals.map((_,i)=>'$'+(i+1)).join(',')}) RETURNING *`,vals); res.status(201).json(r.rows[0]);}catch(e){res.status(400).json({error:'Não foi possível inserir o registro'});} });
app.put('/api/records/:id',auth,async(req,res)=>{ try{const cols=await columns(); const allowed=cols.map(c=>c.column_name).filter(k=>!['id','created_at','updated_at'].includes(k)&&Object.hasOwn(req.body,k)); if(!allowed.length) return res.status(400).json({error:'Nenhum campo informado'}); const vals=allowed.map(k=>req.body[k]); vals.push(req.params.id); const set=allowed.map((k,i)=>`${q(k)}=$${i+1}`).join(','); const r=await pool.query(`UPDATE ${q(schema)}.${q(table)} SET ${set} WHERE ${q('id')}=$${vals.length} RETURNING *`,vals); if(!r.rowCount)return res.status(404).json({error:'Registro não encontrado'}); res.json(r.rows[0]);}catch(e){res.status(400).json({error:'Não foi possível atualizar o registro'});} });
app.use(express.static(path.join(__dirname,'dist')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'dist','index.html')));
app.listen(process.env.PORT||3000,()=>console.log('lusean-admin ativo'));
