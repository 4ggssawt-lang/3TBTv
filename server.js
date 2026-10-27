const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const UPLOADS = path.join(ROOT, 'uploads');
fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(UPLOADS, { recursive: true });

const db = new Database(path.join(DATA, '3tbtv.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admins (
 id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS shows (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
 description TEXT DEFAULT '', category TEXT DEFAULT 'مسلسلات',
 year TEXT DEFAULT '', poster TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS episodes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, show_id INTEGER NOT NULL,
 title TEXT NOT NULL, description TEXT DEFAULT '', season INTEGER NOT NULL DEFAULT 1,
 episode_number INTEGER NOT NULL DEFAULT 1, video TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(show_id) REFERENCES shows(id) ON DELETE CASCADE
);
`);
db.pragma('foreign_keys = ON');

if (!db.prepare('SELECT id FROM admins WHERE id=1').get()) {
  db.prepare('INSERT INTO admins(id,username,password_hash,must_change_password) VALUES(1,?,?,1)')
    .run('abo3tb', bcrypt.hashSync('1212as', 12));
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8*60*60*1000 }
}));
app.use('/uploads', express.static(UPLOADS, { maxAge: '1h', setHeaders(res) { res.setHeader('X-Content-Type-Options', 'nosniff'); } }));
app.use(express.static(path.join(ROOT, 'public')));

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 10);
    cb(null, `${Date.now()}-${crypto.randomBytes(5).toString('hex')}${ext}`);
  }
});
const upload = multer({
  storage, limits: { fileSize: 2 * 1024 * 1024 * 1024, files: 2 },
  fileFilter: (_req, file, cb) => {
    const isVideo = file.fieldname === 'video';
    const allowed = isVideo
      ? ['video/mp4','video/webm','video/ogg','application/octet-stream']
      : ['image/jpeg','image/png','image/webp','image/avif'];
    cb(allowed.includes(file.mimetype) ? null : new Error('نوع الملف غير مدعوم'), allowed.includes(file.mimetype));
  }
});
const adminOnly = (req,res,next) => req.session.admin ? next() : res.status(401).json({error:'يلزم تسجيل دخول الأدمن'});
const passwordChanged = (req,res,next) => req.session.mustChangePassword ? res.status(403).json({error:'غيّر كلمة المرور أولاً',mustChangePassword:true}) : next();

app.get('/api/shows', (_req,res) => {
  res.json(db.prepare(`SELECT s.id,s.title,s.description,s.category,s.year,s.poster,s.created_at,
    COUNT(e.id) AS episode_count FROM shows s LEFT JOIN episodes e ON e.show_id=s.id
    GROUP BY s.id ORDER BY s.id DESC`).all());
});
app.get('/api/shows/:id', (req,res) => {
  const show = db.prepare('SELECT * FROM shows WHERE id=?').get(Number(req.params.id));
  if (!show) return res.status(404).json({error:'المسلسل غير موجود'});
  const episodes = db.prepare('SELECT id,title,description,season,episode_number,created_at FROM episodes WHERE show_id=? ORDER BY season,episode_number').all(show.id);
  res.json({...show, episodes});
});
app.get('/api/episodes/:id', (req,res) => {
  const ep = db.prepare(`SELECT e.id,e.show_id,e.title,e.description,e.season,e.episode_number,e.video,s.title AS show_title
    FROM episodes e JOIN shows s ON s.id=e.show_id WHERE e.id=?`).get(Number(req.params.id));
  if (!ep) return res.status(404).json({error:'الحلقة غير موجودة'});
  res.json(ep);
});
app.post('/api/admin/login', (req,res) => {
  const {username,password} = req.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE username=?').get(String(username||''));
  if (!admin || !bcrypt.compareSync(String(password||''),admin.password_hash)) return res.status(401).json({error:'اسم المستخدم أو كلمة المرور غير صحيحة'});
  req.session.admin = true;
  req.session.mustChangePassword = Boolean(admin.must_change_password);
  res.json({ok:true,mustChangePassword:req.session.mustChangePassword});
});
app.post('/api/admin/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/status',(req,res)=>res.json({loggedIn:Boolean(req.session.admin),mustChangePassword:Boolean(req.session.mustChangePassword)}));
app.post('/api/admin/change-password',adminOnly,(req,res)=>{
  const {currentPassword,newPassword}=req.body||{};
  const admin=db.prepare('SELECT * FROM admins WHERE id=1').get();
  if(!bcrypt.compareSync(String(currentPassword||''),admin.password_hash)) return res.status(400).json({error:'كلمة المرور الحالية غير صحيحة'});
  if(typeof newPassword!=='string'||newPassword.length<10) return res.status(400).json({error:'كلمة المرور الجديدة يجب أن تكون 10 أحرف على الأقل'});
  db.prepare('UPDATE admins SET password_hash=?,must_change_password=0 WHERE id=1').run(bcrypt.hashSync(newPassword,12));
  req.session.mustChangePassword=false;
  res.json({ok:true});
});
app.post('/api/admin/shows',adminOnly,passwordChanged,upload.fields([{name:'poster',maxCount:1}]),(req,res)=>{
  const {title,description='',category='مسلسلات',year=''}=req.body;
  if(!title?.trim()) return res.status(400).json({error:'اسم المسلسل مطلوب'});
  const poster=req.files?.poster?.[0] ? '/uploads/'+req.files.poster[0].filename : '';
  const result=db.prepare('INSERT INTO shows(title,description,category,year,poster) VALUES(?,?,?,?,?)')
    .run(title.trim(),description.trim(),category.trim(),year.trim(),poster);
  res.json({ok:true,id:result.lastInsertRowid});
});
app.post('/api/admin/episodes',adminOnly,passwordChanged,upload.single('video'),(req,res)=>{
  const {show_id,title,description='',season='1',episode_number='1'}=req.body;
  if(!show_id||!title?.trim()||!req.file) return res.status(400).json({error:'اختر مسلسلًا وأدخل اسم الحلقة وملف الفيديو'});
  if(!db.prepare('SELECT id FROM shows WHERE id=?').get(Number(show_id))) return res.status(400).json({error:'المسلسل المحدد غير موجود'});
  const s=Math.max(1,parseInt(season,10)||1), n=Math.max(1,parseInt(episode_number,10)||1);
  const result=db.prepare('INSERT INTO episodes(show_id,title,description,season,episode_number,video) VALUES(?,?,?,?,?,?)')
    .run(Number(show_id),title.trim(),description.trim(),s,n,'/uploads/'+req.file.filename);
  res.json({ok:true,id:result.lastInsertRowid});
});
app.delete('/api/admin/shows/:id',adminOnly,passwordChanged,(req,res)=>{
  const id=Number(req.params.id);
  const show=db.prepare('SELECT poster FROM shows WHERE id=?').get(id);
  if(!show) return res.status(404).json({error:'المسلسل غير موجود'});
  const eps=db.prepare('SELECT video FROM episodes WHERE show_id=?').all(id);
  for(const url of [show.poster,...eps.map(e=>e.video)]) removeUpload(url);
  db.prepare('DELETE FROM episodes WHERE show_id=?').run(id);
  db.prepare('DELETE FROM shows WHERE id=?').run(id);
  res.json({ok:true});
});
app.delete('/api/admin/episodes/:id',adminOnly,passwordChanged,(req,res)=>{
  const ep=db.prepare('SELECT video FROM episodes WHERE id=?').get(Number(req.params.id));
  if(!ep) return res.status(404).json({error:'الحلقة غير موجودة'});
  removeUpload(ep.video); db.prepare('DELETE FROM episodes WHERE id=?').run(Number(req.params.id)); res.json({ok:true});
});
function removeUpload(url) {
  if(url && url.startsWith('/uploads/')) {
    const p=path.join(UPLOADS,path.basename(url));
    if(fs.existsSync(p)) fs.unlinkSync(p);
  }
}
app.get('/paneladmin',(_req,res)=>res.sendFile(path.join(ROOT,'public','admin.html')));
app.use((err,_req,res,_next)=>{ console.error(err.message); res.status(400).json({error:err.message||'حدث خطأ في الطلب'}); });
app.listen(PORT,()=>console.log(`3TBTV v2 running at http://localhost:${PORT}`));
