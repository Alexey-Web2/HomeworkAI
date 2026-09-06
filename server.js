require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const OpenAI = require('openai');
const { GoogleGenAI } = require('@google/genai');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const COOKIE_NAME = process.env.COOKIE_NAME || 'homeworkai_token';
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('Supabase environment variables are required');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

const SUBJECTS = [
  'Алгебра','Геометрия','Физика','Русская литература/язык','Белорусская литература/язык',
  'Информатика','История Всемирная/Беларуси','Биология','География','Английский','Химия'
];
const PLANS = {
  Standard: { price: 0, days: 0, models: [], messages12h: 0 },
  Start: { price: 25, days: 7, models: ['chatgpt'], messages12h: 5 },
  Plus: { price: 50, days: 7, models: ['chatgpt','gemini'], messages12h: 10 },
  Pro: { price: 100, days: 7, models: ['chatgpt','gemini'], messages12h: Infinity }
};

const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;
const deepseek = process.env.DEEPSEEK_API_KEY ? new OpenAI({
  apiKey: process.env.DEEPSEEK_API_KEY,
  baseURL: process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com'
}) : null;
const gemini = process.env.GEMINI_API_KEY ? new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY }) : null;

function nowIso() { return new Date().toISOString(); }
function normalizeTelegram(value) { return String(value || '').trim().replace(/^@/, '').toLowerCase(); }
function normalizeUsername(value) { return String(value || '').trim(); }
function validUsername(value) { return /^[A-Za-z0-9_-]{1,20}$/.test(value); }
function containsEmoji(value) { return /[\u{1F300}-\u{1FAFF}\u{1F1E6}-\u{1F1FF}\u2600-\u27BF\u{1F900}-\u{1F9FF}]/u.test(value); }
function randomCode() { return crypto.randomInt(100000, 1000000).toString(); }
function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function effectivePlan(user) {
  if (!user || !user.plan) return 'Standard';
  if (user.plan !== 'Standard' && user.plan_expires_at && new Date(user.plan_expires_at) <= new Date()) return 'Standard';
  return user.plan;
}
function safeUser(user) {
  return {
    id: user.id,
    username: user.username,
    telegram_username: user.telegram_username,
    role: user.role,
    status: user.status,
    plan: effectivePlan(user),
    plan_expires_at: user.plan_expires_at,
    created_at: user.created_at,
    updated_at: user.updated_at
  };
}
function signAuth(user) { return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' }); }
function writeAuth(res, user) {
  res.cookie(COOKIE_NAME, signAuth(user), {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',
    maxAge: 7 * 24 * 3600 * 1000,
    path: '/'
  });
}
function clearAuth(res) { res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', path: '/' }); }
function getToken(req) { try { return jwt.verify(req.cookies?.[COOKIE_NAME] || '', JWT_SECRET); } catch { return null; } }
function sendError(res, status, message, extra = {}) { return res.status(status).json({ ok: false, error: message, ...extra }); }

app.disable('x-powered-by');
app.set('trust proxy', 1);
const origins = (process.env.APP_URL || `http://localhost:${PORT}`).split(',').map(v => v.trim()).filter(Boolean);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: (origin, cb) => cb(null, !origin || origins.includes(origin)), credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '200kb' }));
app.use(cookieParser());
app.use(express.static(path.join(ROOT, 'public'), { maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false });
const aiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const verifyLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
app.use('/api/auth', authLimiter);
app.use('/api/ai', aiLimiter);
app.use('/api/auth/register/verify', verifyLimiter);

async function loadUser(req, _res, next) {
  const token = getToken(req);
  if (!token) return next();
  const { data, error } = await supabase.from('users').select('*').eq('id', token.sub).maybeSingle();
  if (!error && data) req.user = data;
  next();
}
async function authRequired(req, res, next) {
  await loadUser(req, res, () => {});
  if (!req.user) return sendError(res, 401, 'Не выполнен вход.');
  next();
}
function roleRequired(...roles) {
  return (req, res, next) => roles.includes(req.user?.role) ? next() : sendError(res, 403, 'Недостаточно прав.');
}
async function serviceRequired(req, res, next) {
  if (req.user?.role === 'admin') return next();
  const { data } = await supabase.from('service_settings').select('stopped,message').eq('id', true).maybeSingle();
  if (data?.stopped) return res.status(503).json({ ok: false, code: 'SERVICE_STOPPED', message: data.message || 'Сервис остановлен.' });
  next();
}

async function cleanupExpired() {
  const current = nowIso();
  const old24 = new Date(Date.now() - 24*3600*1000).toISOString();
  await Promise.allSettled([
    supabase.from('announcements').delete().lt('expires_at', current),
    supabase.from('ai_solutions').delete().lt('expires_at', current),
    supabase.from('ai_chat_messages').delete().lt('expires_at', current),
    supabase.from('support_chats').delete().lt('updated_at', old24),
    supabase.from('telegram_verifications').delete().or(`expires_at.lt.${current},used.eq.true`),
    supabase.from('registration_requests').delete().eq('status','approved').lt('created_at', new Date(Date.now() - 30*24*3600*1000).toISOString())
  ]);
}
setInterval(cleanupExpired, 10 * 60 * 1000).unref();

async function seedBase() {
  const { data: existingAdmin } = await supabase.from('users').select('id,role,password_hash').eq('username', process.env.ADMIN_USERNAME || 'Admin').maybeSingle();
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminPassword) {
    const hash = await bcrypt.hash(adminPassword, 12);
    if (!existingAdmin) {
      await supabase.from('users').insert({ username: process.env.ADMIN_USERNAME || 'Admin', telegram_username: 'admin', password_hash: hash, role: 'admin', status: 'approved', plan: 'Pro' });
    } else if (existingAdmin.role !== 'admin' || !(await bcrypt.compare(adminPassword, existingAdmin.password_hash))) {
      await supabase.from('users').update({ role: 'admin', status: 'approved', password_hash: hash, plan: 'Pro' }).eq('id', existingAdmin.id);
    }
  }
  for (const subject of SUBJECTS) {
    await supabase.from('homework').upsert({ subject, title: '', body: '', due_text: '' }, { onConflict: 'subject', ignoreDuplicates: true });
  }
  await supabase.from('service_settings').upsert({ id: true, stopped: false, message: '' }, { onConflict: 'id', ignoreDuplicates: true });
  await supabase.from('faq').upsert({ id: true, content: 'Вставьте сюда ваш FAQ.' }, { onConflict: 'id', ignoreDuplicates: true });
}

async function textbookSearch(subject, question, limit = 8) {
  const words = `${subject} ${question}`.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(v => v.length >= 4).slice(0, 12);
  if (!words.length) return [];
  const filters = words.map(w => `content.ilike.%${w.replace(/[%_,]/g, '')}%`).join(',');
  const { data } = await supabase.from('textbook_chunks').select('id,book_title,chapter,content').eq('subject', subject).or(filters).limit(limit);
  return data || [];
}
async function embeddingFor(text) {
  if (!openai) return null;
  const result = await openai.embeddings.create({ model: process.env.OPENAI_EMBEDDING_MODEL || 'text-embedding-3-small', input: text.slice(0, 8000) });
  return result.data?.[0]?.embedding || null;
}
async function vectorSearch(subject, text, limit = 8) {
  try {
    const embedding = await embeddingFor(text);
    if (!embedding) return [];
    const { data, error } = await supabase.rpc('match_textbook_chunks', {
      query_embedding: embedding,
      match_threshold: Number(process.env.RAG_MATCH_THRESHOLD || 0.25),
      match_count: limit,
      filter_subject: subject
    });
    if (error) return [];
    return data || [];
  } catch { return []; }
}
async function getKnowledge(subject, question) {
  const [vector, keyword, faq] = await Promise.all([
    vectorSearch(subject, question, 8),
    textbookSearch(subject, question, 8),
    supabase.from('faq').select('content').eq('id', true).maybeSingle()
  ]);
  const merged = new Map();
  for (const item of [...vector, ...keyword]) merged.set(item.id || `${item.book_title}:${item.chapter}:${item.content.slice(0,20)}`, item);
  return { chunks: [...merged.values()].slice(0, 10), faq: faq.data?.content || '' };
}

async function callAI(modelKey, messages) {
  if (modelKey === 'chatgpt') {
    if (!openai) throw new Error('OPENAI_API_KEY не настроен.');
    const r = await openai.responses.create({ model: process.env.OPENAI_MODEL || 'gpt-5', input: messages, store: false });
    return r.output_text || '';
  }
  if (modelKey === 'gemini') {
    if (!gemini) throw new Error('GEMINI_API_KEY не настроен.');
    const system = messages.find(m => m.role === 'system')?.content || '';
    const user = messages.filter(m => m.role !== 'system').map(m => `${m.role.toUpperCase()}: ${m.content}`).join('\n\n');
    const result = await gemini.models.generateContent({ model: process.env.GEMINI_MODEL || 'gemini-3.7-flash', contents: `${system}\n\n${user}` });
    return result.text || '';
  }
  if (modelKey === 'deepseek') {
    if (!deepseek) throw new Error('DEEPSEEK_API_KEY не настроен.');
    const r = await deepseek.chat.completions.create({ model: process.env.DEEPSEEK_MODEL || 'deepseek-chat', messages, temperature: 0.2 });
    return r.choices?.[0]?.message?.content || '';
  }
  throw new Error('Неизвестная AI-модель.');
}
function modelAllowed(user, model) { return PLANS[effectivePlan(user)]?.models.includes(model); }
async function usageFor(userId) {
  const since = new Date(Date.now() - 12*3600*1000).toISOString();
  const { count } = await supabase.from('ai_chat_messages').select('id', { count: 'exact', head: true }).eq('user_id', userId).eq('role','user').gte('created_at', since);
  return count || 0;
}
async function checkChatQuota(user) {
  const plan = PLANS[effectivePlan(user)] || PLANS.Standard;
  if (plan.messages12h === Infinity) return { allowed: true, used: await usageFor(user.id), limit: Infinity };
  const used = await usageFor(user.id);
  return { allowed: used < plan.messages12h, used, limit: plan.messages12h };
}

// ---------------- auth ----------------
app.get('/api/health', (_req,res) => res.json({ ok: true, service: 'HomeworkAI', time: nowIso() }));
app.get('/api/auth/me', authRequired, async (req,res) => res.json({ ok: true, user: safeUser(req.user) }));
app.post('/api/auth/logout', (_req,res) => { clearAuth(res); res.json({ ok: true }); });
app.post('/api/auth/login', async (req,res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || '');
  if (!username || !password) return sendError(res, 400, 'Заполните никнейм и пароль.');
  const { data: user } = await supabase.from('users').select('*').eq('username', username).maybeSingle();
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return sendError(res, 401, 'Неверный никнейм или пароль.');
  writeAuth(res, user);
  return res.json({ ok: true, user: safeUser(user) });
});

console.log('[AUTH] register/start route loaded');

app.post('/api/auth/register/start', async (req,res) => {
  const telegram = normalizeTelegram(req.body.telegram_username);
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(telegram)) return sendError(res,400,'Введите корректный Telegram username.');
  
  if (!global.telegramSend) {
    return sendError(res, 500, 'Telegram-бот не инициализирован на сервере. Проверьте TELEGRAM_BOT_TOKEN.');
  }

  const { data: existing } = await supabase.from('users').select('id').eq('telegram_username', telegram).maybeSingle();
  if (existing) return sendError(res,409,'Этот Telegram уже используется.');
  
  const { data: link } = await supabase.from('telegram_links').select('chat_id,verified').eq('username',telegram).maybeSingle();
  if (!link?.chat_id) {
    return sendError(res,400,`Откройте бота в Telegram, нажмите кнопку Начать (/start), затем повторите этот шаг. Ваш Username: @${telegram}`, { code: 'TELEGRAM_START_REQUIRED' });
  }

  const code = randomCode();
  const expires = new Date(Date.now()+5*60*1000).toISOString();
  await supabase.from('telegram_verifications').delete().eq('telegram_username',telegram);
  const { error } = await supabase.from('telegram_verifications').insert({ telegram_username:telegram, telegram_chat_id:link.chat_id, code_hash:sha256(code), expires_at:expires, used:false });
  if (error) return sendError(res,500,'Не удалось создать код подтверждения.');
  
  try {
    await global.telegramSend(link.chat_id, `HomeworkAI\n\nКод подтверждения регистрации: ${code}\n\nКод действует 5 минут. Не передавайте его другим людям.`);
    res.json({ ok: true, telegram, expires_at: expires });
  } catch (err) {
    console.error('Ошибка отправки сообщения в Telegram:', err);
    return sendError(res, 500, 'Не удалось отправить сообщение в Telegram. Убедитесь, что вы запустили бота.');
  }
});

app.post('/api/auth/register/verify', async (req,res) => {
  const telegram = normalizeTelegram(req.body.telegram_username);
  const code = String(req.body.code || '').trim();
  if (!telegram || !/^\d{6}$/.test(code)) return sendError(res,400,'Введите шестизначный код.');
  const { data: row } = await supabase.from('telegram_verifications').select('*').eq('telegram_username',telegram).eq('used',false).maybeSingle();
  if (!row || new Date(row.expires_at) <= new Date() || !crypto.timingSafeEqual(Buffer.from(row.code_hash), Buffer.from(sha256(code)))) return sendError(res,400,'Код неверный или уже недействителен.');
  await supabase.from('telegram_verifications').update({ used:true }).eq('id',row.id);
  res.json({ ok:true, verified:true });
});

app.post('/api/auth/register/check-username', async (req,res) => {
  const username = normalizeUsername(req.body.username);
  if (!validUsername(username)) return sendError(res,400,'Никнейм: 1–20 символов, только английские буквы, цифры, _ и -.');
  const { data } = await supabase.from('users').select('id').eq('username',username).maybeSingle();
  res.json({ ok:true, available:!data });
});

app.post('/api/auth/register/finish', async (req,res) => {
  const telegram = normalizeTelegram(req.body.telegram_username);
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || '');
  if (!validUsername(username)) return sendError(res,400,'Недопустимый никнейм.');
  if (!password || containsEmoji(password)) return sendError(res,400,'Пароль не может быть пустым и не должен содержать смайлики.');
  const { data: verified } = await supabase.from('telegram_verifications').select('*').eq('telegram_username',telegram).eq('used',true).order('created_at',{ascending:false}).maybeSingle();
  if (!verified || new Date(verified.created_at) < new Date(Date.now()-10*60*1000)) return sendError(res,400,'Telegram-подтверждение устарело. Начните регистрацию заново.');
  const { data: duplicate } = await supabase.from('users').select('id').eq('username',username).maybeSingle();
  if (duplicate) return sendError(res,409,'Этот никнейм уже используется.');
  const { data: telegramDuplicate } = await supabase.from('users').select('id').eq('telegram_username',telegram).maybeSingle();
  if (telegramDuplicate) return sendError(res,409,'Этот Telegram уже используется.');
  const password_hash = await bcrypt.hash(password,12);
  const { data: user, error } = await supabase.from('users').insert({ username, telegram_username:telegram, telegram_chat_id:verified.telegram_chat_id, password_hash, role:'user', status:'pending', plan:'Standard' }).select('*').single();
  if (error) return sendError(res,500,'Не удалось создать аккаунт.');
  await supabase.from('registration_requests').insert({ user_id:user.id, status:'pending' });
  writeAuth(res,user);
  res.json({ ok:true, user:safeUser(user) });
});

// ---------------- common/service ----------------
app.get('/api/service-status', async (_req,res) => {
  const { data } = await supabase.from('service_settings').select('*').eq('id',true).maybeSingle();
  res.json({ ok:true, stopped:!!data?.stopped, message:data?.message || '' });
});

// ---------------- home ----------------
app.get('/api/home', authRequired, serviceRequired, async (req,res) => {
  const [{ data: homework }, { data: announcements }] = await Promise.all([
    supabase.from('homework').select('*').order('subject'),
    supabase.from('announcements').select('*').gt('expires_at',nowIso()).order('created_at',{ascending:false})
  ]);
  const [{ data: solutions }] = await Promise.all([
    supabase.from('ai_solutions').select('id,homework_id,subject,question,solution,created_at,expires_at').eq('user_id',req.user.id).gt('expires_at',nowIso()).order('created_at',{ascending:false})
  ]);
  const quota = await checkChatQuota(req.user);
  res.json({ ok:true, subjects:SUBJECTS, homework:homework||[], announcements:announcements||[], solutions:solutions||[], quota, plan:effectivePlan(req.user) });
});

// ---------------- AI homework ----------------
app.post('/api/ai/solve/:homeworkId', authRequired, serviceRequired, aiLimiter, async (req,res) => {
  const model = req.body.model || 'chatgpt';
  if (!modelAllowed(req.user,model)) return sendError(res,403,`Модель ${model} недоступна на вашем плане.`);
  const { data: hw } = await supabase.from('homework').select('*').eq('id',req.params.homeworkId).maybeSingle();
  if (!hw) return sendError(res,404,'Домашнее задание не найдено.');
  if (!hw.body.trim()) return sendError(res,400,'Для этого предмета пока нет домашнего задания.');
  const existing = await supabase.from('ai_solutions').select('*').eq('user_id',req.user.id).eq('homework_id',hw.id).gt('expires_at',nowIso()).maybeSingle();
  if (existing.data) return res.json({ ok:true, cached:true, solution:existing.data });
  const knowledge = await getKnowledge(hw.subject, hw.body);
  const context = knowledge.chunks.map(x => `[${x.book_title}${x.chapter ? ` / ${x.chapter}` : ''}]\n${x.content}`).join('\n\n');
  const messages = [
    { role:'system', content:`Ты HomeworkAI — школьный помощник. Решай домашнее задание подробно и проверяемо. Предпочитай знания из предоставленного учебника, но не выдумывай цитаты. Если учебника недостаточно, решай самостоятельно и честно отмечай это. Для математики показывай промежуточные шаги. Для гуманитарных предметов структурируй ответ и указывай аргументы. Ответ на русском языке. Предмет: ${hw.subject}. Контекст учебников:\n${context || 'В базе пока нет подходящего фрагмента.'}` },
    { role:'user', content:`Домашнее задание:\n${hw.body}\n\nСделай готовое решение с объяснением.` }
  ];
  try {
    const solutionText = await callAI(model,messages);
    const expires = new Date(Date.now()+24*3600*1000).toISOString();
    const { data: saved, error } = await supabase.from('ai_solutions').insert({ user_id:req.user.id, homework_id:hw.id, subject:hw.subject, question:hw.body, solution:solutionText, model, expires_at:expires }).select('*').single();
    if (error) return sendError(res,500,'Ответ получен, но сохранить решение не удалось.');
    res.json({ ok:true, cached:false, solution:saved });
  } catch (e) { sendError(res,502,e.message || 'AI недоступен.'); }
});

app.get('/api/ai/solutions', authRequired, serviceRequired, async (req,res) => {
  const { data } = await supabase.from('ai_solutions').select('*').eq('user_id',req.user.id).gt('expires_at',nowIso()).order('created_at',{ascending:false});
  res.json({ ok:true, solutions:data||[] });
});

app.delete('/api/ai/chat/history', authRequired, serviceRequired, async (req,res) => {
  await supabase.from('ai_chat_messages').delete().eq('user_id',req.user.id);
  res.json({ok:true});
});
app.get('/api/ai/chat/history', authRequired, serviceRequired, async (req,res) => {
  const { data } = await supabase.from('ai_chat_messages').select('*').eq('user_id',req.user.id).gt('expires_at',nowIso()).order('created_at');
  res.json({ ok:true, messages:data||[], quota:await checkChatQuota(req.user), plan:effectivePlan(req.user) });
});
app.post('/api/ai/chat', authRequired, serviceRequired, aiLimiter, async (req,res) => {
  const subject = String(req.body.subject || 'Общее').slice(0,120);
  const model = String(req.body.model || 'chatgpt');
  const content = String(req.body.message || '').trim();
  if (!content) return sendError(res,400,'Введите вопрос.');
  if (!modelAllowed(req.user,model)) return sendError(res,403,'Эта модель недоступна на вашем плане.');
  const quota = await checkChatQuota(req.user);
  if (!quota.allowed) return sendError(res,429,`Лимит сообщений исчерпан: ${quota.limit} сообщений за 12 часов.`);
  const { data: recent } = await supabase.from('ai_chat_messages').select('role,content,subject,model').eq('user_id',req.user.id).gt('expires_at',nowIso()).order('created_at',{ascending:false}).limit(16);
  const knowledge = await getKnowledge(subject, content);
  const context = knowledge.chunks.map(x => `[${x.book_title}${x.chapter ? ` / ${x.chapter}` : ''}]\n${x.content}`).join('\n\n');
  const messages = [{ role:'system', content:`Ты школьный AI HomeworkAI. Помогаешь ученику по предмету «${subject}». Объясняй понятным русским языком. Используй базу учебников ниже, когда она релевантна. Не выдавай выдуманные ссылки или страницы.\n\nУчебники:\n${context || 'Подходящих фрагментов нет.'}` }, ...(recent||[]).reverse().map(x=>({role:x.role,content:x.content})), { role:'user', content }];
  try {
    const answer = await callAI(model,messages);
    const expires = new Date(Date.now()+24*3600*1000).toISOString();
    await supabase.from('ai_chat_messages').insert([
      { user_id:req.user.id, subject, model, role:'user', content, expires_at:expires },
      { user_id:req.user.id, subject, model, role:'assistant', content:answer, expires_at:expires }
    ]);
    const updated = await checkChatQuota(req.user);
    res.json({ ok:true, answer, quota:updated });
  } catch (e) { sendError(res,502,e.message || 'AI недоступен.'); }
});

// ---------------- plans ----------------
app.get('/api/plans', authRequired, serviceRequired, async (req,res) => res.json({ ok:true, plans:PLANS, current:effectivePlan(req.user), expires_at:req.user.plan_expires_at }));
app.post('/api/plans/request', authRequired, serviceRequired, async (req,res) => {
  const plan = String(req.body.plan || '');
  if (!['Start','Plus','Pro'].includes(plan)) return sendError(res,400,'Недопустимый план.');
  const { data: exists } = await supabase.from('plan_requests').select('id').eq('user_id',req.user.id).eq('status','pending').maybeSingle();
  if (exists) return sendError(res,409,'У вас уже есть ожидающий запрос на план.');
  const { data, error } = await supabase.from('plan_requests').insert({ user_id:req.user.id, requested_plan:plan, status:'pending' }).select('*').single();
  if (error) return sendError(res,500,'Не удалось создать запрос.');
  res.json({ ok:true, request:data });
});

// ---------------- support ----------------
async function ensureSupportChat(userId) {
  const { data: existing } = await supabase.from('support_chats').select('*').eq('user_id',userId).eq('status','open').maybeSingle();
  if (existing) return existing;
  const { data } = await supabase.from('support_chats').insert({ user_id:userId, ai_enabled:true, human_requested:false, status:'open' }).select('*').single();
  return data;
}
app.get('/api/support', authRequired, serviceRequired, async (req,res) => {
  const chat = await ensureSupportChat(req.user.id);
  const [{ data:messages }, { data:faq }] = await Promise.all([
    supabase.from('support_messages').select('*').eq('chat_id',chat.id).order('created_at'),
    supabase.from('faq').select('content').eq('id',true).maybeSingle()
  ]);
  res.json({ ok:true, chat, messages:messages||[], faq:faq?.content||'' });
});
app.post('/api/support/message', authRequired, serviceRequired, aiLimiter, async (req,res) => {
  const content = String(req.body.content || '').trim();
  if (!content) return sendError(res,400,'Введите сообщение.');
  const chat = await ensureSupportChat(req.user.id);
  await supabase.from('support_messages').insert({ chat_id:chat.id, sender_type:'user', content });
  if (!chat.ai_enabled || chat.human_requested) return res.json({ ok:true, human_mode:true });
  const { data:faq } = await supabase.from('faq').select('content').eq('id',true).maybeSingle();
  const { data:history } = await supabase.from('support_messages').select('sender_type,content').eq('chat_id',chat.id).order('created_at',{ascending:false}).limit(20);
  const prompt = `Ты AI поддержки HomeworkAI. Отвечай кратко, вежливо и по делу. Ниже FAQ, которым нужно пользоваться. Если вопрос требует действий человека — начни ответ с маркера HUMAN_NEEDED. В остальных случаях начни с AI_ONLY.\n\nFAQ:\n${(faq?.content||'Нет FAQ').slice(0,30000)}\n\nСообщение пользователя:\n${content}`;
  let answer;
  try {
    answer = await callAI('gemini', [
        { role:'system', content:prompt },
        ...((history||[]).reverse().map(x=>({
            role:x.sender_type==='user'?'user':'assistant',
            content:x.content
        })))
    ]);
  } catch (e) { return sendError(res,502,e.message || 'AI поддержки недоступен.'); }
  const human = /^\s*HUMAN_NEEDED/i.test(answer) || /позвать человека|оператора|администратора/i.test(answer);
  const cleaned = answer.replace(/^\s*(HUMAN_NEEDED|AI_ONLY)\s*[:\-]?\s*/i,'').trim();
  await supabase.from('support_messages').insert({ chat_id:chat.id, sender_type:'ai', content:cleaned || answer });
  await supabase.from('support_chats').update({ ai_enabled:!human, human_requested:human, updated_at:nowIso() }).eq('id',chat.id);
  res.json({ ok:true, answer:cleaned || answer, human_requested:human, ai_enabled:!human });
});
app.post('/api/support/request-human', authRequired, serviceRequired, async (req,res) => {
  const chat = await ensureSupportChat(req.user.id);
  await supabase.from('support_chats').update({ ai_enabled:false, human_requested:true, updated_at:nowIso() }).eq('id',chat.id);
  await supabase.from('support_messages').insert({ chat_id:chat.id, sender_type:'system', content:'Пользователь запросил человека.' }).then(()=>{});
  res.json({ ok:true });
});
app.post('/api/support/close', authRequired, serviceRequired, async (req,res) => {
  const { data: chat } = await supabase.from('support_chats').select('id').eq('user_id',req.user.id).eq('status','open').maybeSingle();
  if (chat) await supabase.from('support_chats').delete().eq('id',chat.id);
  res.json({ ok:true });
});
app.get('/api/faq', authRequired, async (_req,res)=>{const {data}=await supabase.from('faq').select('content').eq('id',true).maybeSingle();res.json({ok:true,content:data?.content||''});});
app.get('/api/account', authRequired, async (req,res)=>res.json({ok:true,user:safeUser(req.user)}));
app.post('/api/account/username', authRequired, serviceRequired, async (req,res)=>{
  const username=normalizeUsername(req.body.username);
  if(!validUsername(username))return sendError(res,400,'Никнейм: 1–20 символов, английские буквы, цифры, _ и -.');
  const {data}=await supabase.from('users').select('id').eq('username',username).maybeSingle();
  if(data&&data.id!==req.user.id)return sendError(res,409,'Этот никнейм уже используется.');
  const {data:updated,error}=await supabase.from('users').update({username,updated_at:nowIso()}).eq('id',req.user.id).select('*').single();
  if(error)return sendError(res,500,'Не удалось изменить никнейм.');
  writeAuth(res,updated);res.json({ok:true,user:safeUser(updated)});
});
app.post('/api/account/password', authRequired, serviceRequired, async (req,res)=>{
  const current=String(req.body.current_password||''), next=String(req.body.new_password||'');
  if(!(await bcrypt.compare(current,req.user.password_hash)))return sendError(res,400,'Текущий пароль неверный.');
  if(!next||containsEmoji(next))return sendError(res,400,'Новый пароль недопустим.');
  const hash=await bcrypt.hash(next,12);
  await supabase.from('users').update({password_hash:hash,updated_at:nowIso()}).eq('id',req.user.id);clearAuth(res);res.json({ok:true});
});
app.post('/api/account/delete-request', authRequired, serviceRequired, async (req,res)=>{
  const {data:existing}=await supabase.from('deletion_requests').select('id').eq('user_id',req.user.id).eq('status','pending').maybeSingle();
  if(existing)return sendError(res,409,'Запрос на удаление уже отправлен.');
  await supabase.from('deletion_requests').insert({user_id:req.user.id,status:'pending'});res.json({ok:true});
});

// ---------------- admin ----------------
app.get('/api/admin/dashboard', authRequired, roleRequired('admin'), async (req,res)=>{
  const since24 = new Date(Date.now()-24*3600*1000).toISOString();
  const [users,reg,del,planReq,chats,hw,ann,service,faq] = await Promise.all([
    supabase.from('users').select('id,username,telegram_username,role,status,plan,plan_expires_at,created_at,updated_at').order('created_at',{ascending:false}),
    supabase.from('registration_requests').select('id,status,created_at,user_id,user:users(id,username,telegram_username)').eq('status','pending').order('created_at'),
    supabase.from('deletion_requests').select('id,status,created_at,user_id,user:users(id,username,telegram_username)').eq('status','pending').order('created_at'),
    supabase.from('plan_requests').select('id,requested_plan,status,created_at,user_id,user:users(id,username,telegram_username)').eq('status','pending').order('created_at'),
    supabase.from('support_chats').select('id,user_id,ai_enabled,human_requested,status,updated_at,created_at,user:users(id,username,telegram_username)').eq('status','open').order('updated_at',{ascending:false}),
    supabase.from('homework').select('*').order('subject'),
    supabase.from('announcements').select('*').gt('expires_at',nowIso()).order('created_at',{ascending:false}),
    supabase.from('service_settings').select('*').eq('id',true).maybeSingle(),
    supabase.from('faq').select('content').eq('id',true).maybeSingle()
  ]);
  const metrics = {
    users:(users.data||[]).length,
    pendingRegistrations:(reg.data||[]).length,
    pendingDeletions:(del.data||[]).length,
    pendingPlans:(planReq.data||[]).length,
    openSupport:(chats.data||[]).length,
    alerts24h:(ann.data||[]).filter(x=>x.created_at>=since24).length
  };
  res.json({ok:true,metrics,users:users.data||[],registration:reg.data||[],deletions:del.data||[],plans:planReq.data||[],support:chats.data||[],homework:hw.data||[],announcements:ann.data||[],service:service.data||{stopped:false,message:''},faq:faq.data?.content||''});
});
app.get('/api/admin/support/:id', authRequired, roleRequired('admin'), async (req,res)=>{
  const {data:chat}=await supabase.from('support_chats').select('*,user:users(id,username,telegram_username)').eq('id',req.params.id).maybeSingle();
  if(!chat)return sendError(res,404,'Чат не найден.');
  const {data:messages}=await supabase.from('support_messages').select('*').eq('chat_id',chat.id).order('created_at');
  res.json({ok:true,chat,messages:messages||[]});
});
app.post('/api/admin/support/:id/message', authRequired, roleRequired('admin'), async (req,res)=>{
  const content=String(req.body.content||'').trim();if(!content)return sendError(res,400,'Сообщение пустое.');
  await supabase.from('support_messages').insert({chat_id:req.params.id,sender_type:'human',content});
  await supabase.from('support_chats').update({ai_enabled:false,human_requested:true,updated_at:nowIso()}).eq('id',req.params.id);res.json({ok:true});
});
app.post('/api/admin/support/:id/close', authRequired, roleRequired('admin'), async (req,res)=>{await supabase.from('support_chats').delete().eq('id',req.params.id);res.json({ok:true});});
app.post('/api/admin/user/:id/action', authRequired, roleRequired('admin'), async (req,res)=>{
  const action=String(req.body.action||'');
  if(req.params.id===req.user.id && ['delete','block','unmanager'].includes(action))return sendError(res,400,'Нельзя выполнить это действие над собой.');
  const {data:user}=await supabase.from('users').select('*').eq('id',req.params.id).maybeSingle();if(!user)return sendError(res,404,'Пользователь не найден.');
  const updates={};
  if(action==='block')updates.status='blocked';
  else if(action==='unblock')updates.status='approved';
  else if(action==='manager')updates.role='manager';
  else if(action==='unmanager')updates.role='user';
  else if(action==='delete'){await supabase.from('users').delete().eq('id',user.id);return res.json({ok:true});}
  else return sendError(res,400,'Неизвестное действие.');
  await supabase.from('users').update({...updates,updated_at:nowIso()}).eq('id',user.id);res.json({ok:true});
});
app.post('/api/admin/user/:id/plan', authRequired, roleRequired('admin'), async (req,res)=>{
  const plan=String(req.body.plan||'Standard');const days=Math.max(0,Math.min(365,Number(req.body.days||7)));
  if(!['Standard','Start','Plus','Pro'].includes(plan))return sendError(res,400,'План недопустим.');
  const expires=plan==='Standard'?null:new Date(Date.now()+days*86400000).toISOString();
  await supabase.from('users').update({plan,plan_expires_at:expires,updated_at:nowIso()}).eq('id',req.params.id);res.json({ok:true});
});
app.post('/api/admin/registration/:id', authRequired, roleRequired('admin'), async (req,res)=>{
  const decision=String(req.body.decision||'');const {data:item}=await supabase.from('registration_requests').select('*').eq('id',req.params.id).maybeSingle();if(!item)return sendError(res,404,'Запрос не найден.');
  if(decision==='approve'){await supabase.from('users').update({status:'approved',updated_at:nowIso()}).eq('id',item.user_id);await supabase.from('registration_requests').update({status:'approved'}).eq('id',item.id);}
  else if(decision==='reject'){await supabase.from('users').update({status:'blocked',updated_at:nowIso()}).eq('id',item.user_id);await supabase.from('registration_requests').update({status:'rejected'}).eq('id',item.id);}
  else return sendError(res,400,'Неверное решение.');res.json({ok:true});
});
app.post('/api/admin/deletion/:id', authRequired, roleRequired('admin'), async (req,res)=>{
  const decision=String(req.body.decision||'');const {data:item}=await supabase.from('deletion_requests').select('*').eq('id',req.params.id).maybeSingle();if(!item)return sendError(res,404,'Запрос не найден.');
  if(decision==='delete'){await supabase.from('users').delete().eq('id',item.user_id);}else if(decision==='reject'){await supabase.from('deletion_requests').update({status:'rejected'}).eq('id',item.id);}else return sendError(res,400,'Неверное решение.');res.json({ok:true});
});
app.post('/api/admin/plan-request/:id', authRequired, roleRequired('admin'), async (req,res)=>{
  const decision=String(req.body.decision||'');const {data:item}=await supabase.from('plan_requests').select('*').eq('id',req.params.id).maybeSingle();if(!item)return sendError(res,404,'Запрос не найден.');
  if(decision==='approve'){await supabase.from('users').update({plan:item.requested_plan,plan_expires_at:new Date(Date.now()+7*86400000).toISOString(),updated_at:nowIso()}).eq('id',item.user_id);await supabase.from('plan_requests').update({status:'approved'}).eq('id',item.id);}
  else if(decision==='reject')await supabase.from('plan_requests').update({status:'rejected'}).eq('id',item.id);else return sendError(res,400,'Неверное решение.');res.json({ok:true});
});
app.put('/api/admin/homework/:id', authRequired, roleRequired('admin','manager'), async (req,res)=>{
  const title=String(req.body.title||'').slice(0,240),body=String(req.body.body||'').slice(0,20000),due_text=String(req.body.due_text||'').slice(0,240);
  const {error}=await supabase.from('homework').update({title,body,due_text,updated_by:req.user.id,updated_at:nowIso()}).eq('id',req.params.id);if(error)return sendError(res,500,'Не удалось сохранить ДЗ.');res.json({ok:true});
});
app.post('/api/admin/homework', authRequired, roleRequired('admin'), async (req,res)=>{
  const subject=String(req.body.subject||'').trim();if(!SUBJECTS.includes(subject))return sendError(res,400,'Предмет недопустим.');
  const {data,error}=await supabase.from('homework').upsert({subject,title:String(req.body.title||''),body:String(req.body.body||''),due_text:String(req.body.due_text||''),updated_by:req.user.id,updated_at:nowIso()},{onConflict:'subject'}).select('*').single();if(error)return sendError(res,500,'Не удалось сохранить.');res.json({ok:true,homework:data});
});
app.post('/api/admin/announcement', authRequired, roleRequired('admin','manager'), async (req,res)=>{
  const title=String(req.body.title||'').trim(),body=String(req.body.body||'').trim(),hours=Math.max(1,Math.min(168,Number(req.body.hours||12)));
  if(!title||!body)return sendError(res,400,'Заголовок и текст обязательны.');
  const {data,error}=await supabase.from('announcements').insert({title,body,expires_at:new Date(Date.now()+hours*3600000).toISOString(),created_by:req.user.id}).select('*').single();if(error)return sendError(res,500,'Не удалось создать оповещение.');res.json({ok:true,announcement:data});
});
app.delete('/api/admin/announcement/:id', authRequired, roleRequired('admin','manager'), async (req,res)=>{await supabase.from('announcements').delete().eq('id',req.params.id);res.json({ok:true});});
app.post('/api/admin/service', authRequired, roleRequired('admin'), async (req,res)=>{const stopped=!!req.body.stopped,message=String(req.body.message||'').slice(0,1000);await supabase.from('service_settings').update({stopped,message,updated_at:nowIso()}).eq('id',true);res.json({ok:true});});
app.put('/api/admin/faq', authRequired, roleRequired('admin'), async (req,res)=>{await supabase.from('faq').update({content:String(req.body.content||'')}).eq('id',true);res.json({ok:true});});

// ---------------- textbook admin ----------------
app.get('/api/admin/textbooks', authRequired, roleRequired('admin'), async (_req,res)=>{const {data}=await supabase.from('textbook_chunks').select('id,subject,book_title,chapter,content,created_at').order('created_at',{ascending:false}).limit(500);res.json({ok:true,chunks:data||[]});});
app.post('/api/admin/textbooks/import', authRequired, roleRequired('admin'), async (req,res)=>{
  const subject=String(req.body.subject||'').trim(),book_title=String(req.body.book_title||'').trim(),chapter=String(req.body.chapter||'').trim(),text=String(req.body.text||'').trim();
  if(!SUBJECTS.includes(subject)||!book_title||!text)return sendError(res,400,'Нужны предмет, название учебника и текст.');
  const size=Math.max(800,Math.min(8000,Number(req.body.chunk_size||3500)));
  const chunks=[];for(let i=0;i<text.length;i+=size){let piece=text.slice(i,i+size);const last=piece.lastIndexOf('\n');if(last>size*0.65){piece=piece.slice(0,last);i-=size-last;}piece=piece.trim();if(piece)chunks.push(piece);}
  const rows=chunks.filter(Boolean).map(content=>({subject,book_title,chapter,content}));
  const {error}=await supabase.from('textbook_chunks').insert(rows);if(error)return sendError(res,500,'Не удалось импортировать учебник.');res.json({ok:true,inserted:rows.length});
});
app.delete('/api/admin/textbooks/:id', authRequired, roleRequired('admin'), async (req,res)=>{await supabase.from('textbook_chunks').delete().eq('id',req.params.id);res.json({ok:true});});
app.post('/api/admin/textbooks/embed', authRequired, roleRequired('admin'), async (req,res)=>{
  if(!openai)return sendError(res,400,'OPENAI_API_KEY не настроен.');
  const limit=Math.max(1,Math.min(100,Number(req.body.limit||25)));
  const {data:rows,error}=await supabase.from('textbook_chunks').select('id,content').is('embedding',null).limit(limit);
  if(error)return sendError(res,500,'Не удалось прочитать учебники.');
  let done=0;
  for(const row of rows||[]){try{const vector=await embeddingFor(row.content);if(vector){await supabase.from('textbook_chunks').update({embedding:vector}).eq('id',row.id);done++;}}catch{}}
  res.json({ok:true,embedded:done,scanned:(rows||[]).length});
});

// ---------------- manager ----------------
app.get('/api/manager/dashboard', authRequired, roleRequired('admin','manager'), async (req,res)=>{
  const [{data:homework},{data:announcements}]=await Promise.all([
    supabase.from('homework').select('*').order('subject'),
    supabase.from('announcements').select('*').gt('expires_at',nowIso()).order('created_at',{ascending:false})
  ]);
  res.json({ok:true,homework:homework||[],announcements:announcements||[]});
});

// ---------------- Telegram ----------------

let telegram = null;

const webhookPath = process.env.TELEGRAM_WEBHOOK_PATH || '/telegram/webhook';

if (process.env.TELEGRAM_BOT_TOKEN) {

    telegram = {

        async call(method, body = {}) {
            const r = await fetch(
                `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/${method}`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(body)
                }
            );

            const json = await r.json();

            if (!json.ok) {
                throw new Error(
                    json.description || 'Telegram API error'
                );
            }

            return json.result;
        },

        async send(chat_id, text, extra = {}) {
            return this.call('sendMessage', {
                chat_id,
                text,
                ...extra
            });
        },

        async registerPrivateChat(msg) {
            const chatId = msg.chat.id;
            const tgUsername = normalizeTelegram(
                msg.from?.username || ''
            );

            if (!tgUsername) {
                await this.send(
                    chatId,
                    `⚠️ У вас не установлен Username в Telegram.

Пожалуйста, укажите @username в настройках Telegram, чтобы сайт смог распознать вас.`
                );

                return null;
            }

            /*
             * ВАЖНО:
             * telegram_links хранит ТОЛЬКО личный chat_id пользователя.
             * Групповые chat_id сюда никогда не записываются.
             */

            const { error } = await supabase
                .from('telegram_links')
                .upsert(
                    {
                        username: tgUsername,
                        chat_id: chatId,
                        verified: true,
                        updated_at: nowIso()
                    },
                    {
                        onConflict: 'username'
                    }
                );

            if (error) {
                console.error(
                    '[Telegram] Ошибка сохранения личного чата:',
                    error
                );

                throw new Error(
                    'Не удалось сохранить Telegram пользователя.'
                );
            }

            return {
                chatId,
                tgUsername
            };
        },

        async registerGroup(msg) {
            const chatId = msg.chat.id;

            if (
                msg.chat.type !== 'group' &&
                msg.chat.type !== 'supergroup'
            ) {
                return;
            }

            const title =
                String(
                    msg.chat.title ||
                    'Без названия'
                ).slice(0, 255);

            const { error } = await supabase
                .from('telegram_groups')
                .upsert(
                    {
                        chat_id: chatId,
                        title,
                        enabled: true,
                        updated_at: nowIso()
                    },
                    {
                        onConflict: 'chat_id'
                    }
                );

            if (error) {
                console.error(
                    '[Telegram] Ошибка сохранения группы:',
                    error
                );
            }
        },

        async sendHomework(chatId) {

            const { data: service } = await supabase
                .from('service_settings')
                .select('*')
                .eq('id', true)
                .maybeSingle();

            if (service?.stopped) {
                return this.send(
                    chatId,
                    `Сервис остановлен\n\n${service.message || ''}`
                );
            }

            const { data: hw, error } = await supabase
                .from('homework')
                .select('*')
                .order('subject');

            if (error) {
                console.error(
                    '[Telegram] Ошибка получения ДЗ:',
                    error
                );

                return this.send(
                    chatId,
                    'Не удалось получить домашнее задание.'
                );
            }

            const lines = (hw || []).map(x => {
                const subject = escapeHtmlTelegram(
                    x.subject
                );

                const body = escapeHtmlTelegram(
                    x.body || 'ДЗ не задано'
                );

                const due = x.due_text
                    ? `\nСрок: ${escapeHtmlTelegram(x.due_text)}`
                    : '';

                return `<b>${subject}</b>\n${body}${due}`;
            });

            const text =
                lines.join('\n\n') ||
                'Домашнее задание пока не задано.';

            return this.send(
                chatId,
                text,
                {
                    parse_mode: 'HTML'
                }
            );
        },

        async sendHomeworkToAllGroups() {

            const { data: groups, error } = await supabase
                .from('telegram_groups')
                .select('chat_id,title')
                .eq('enabled', true);

            if (error) {
                console.error(
                    '[Telegram] Ошибка получения групп:',
                    error
                );

                return {
                    sent: 0,
                    failed: 0
                };
            }

            let sent = 0;
            let failed = 0;

            for (const group of groups || []) {

                try {

                    await this.sendHomework(
                        group.chat_id
                    );

                    sent++;

                } catch (err) {

                    failed++;

                    console.error(
                        `[Telegram] Не удалось отправить ДЗ в группу ${group.chat_id}:`,
                        err.message
                    );

                    /*
                     * Если бота удалили из группы или чат больше
                     * недоступен, отключаем группу.
                     */
                    if (
                        /chat not found/i.test(err.message) ||
                        /bot was kicked/i.test(err.message) ||
                        /forbidden/i.test(err.message)
                    ) {
                        await supabase
                            .from('telegram_groups')
                            .update({
                                enabled: false,
                                updated_at: nowIso()
                            })
                            .eq(
                                'chat_id',
                                group.chat_id
                            );
                    }
                }
            }

            console.log(
                `[Telegram] ДЗ отправлено в группы: ${sent}, ошибок: ${failed}`
            );

            return {
                sent,
                failed
            };
        },

        async handle(update) {

            const msg = update?.message;

            if (!msg?.text) {
                return;
            }

            const text = msg.text.trim();

            const chatId = msg.chat.id;

            const chatType = msg.chat.type;

            const tgUsername = normalizeTelegram(
                msg.from?.username || ''
            );

            /*
             * ------------------------------------------------
             * ГРУППА / СУПЕРГРУППА
             * ------------------------------------------------
             */

            if (
                chatType === 'group' ||
                chatType === 'supergroup'
            ) {

                /*
                 * Сохраняем группу отдельно.
                 * НИКОГДА не записываем её в telegram_links.
                 */
                await this.registerGroup(msg);

                /*
                 * /dz разрешён в группах.
                 *
                 * Поддерживается:
                 * /dz
                 * /dz@ИмяБота
                 */
                if (
                    /^\/dz(?:@\w+)?$/i.test(text)
                ) {

                    try {

                        await this.sendHomework(
                            chatId
                        );

                    } catch (err) {

                        console.error(
                            '[Telegram] Ошибка отправки ДЗ в группу:',
                            err
                        );
                    }

                    return;
                }

                /*
                 * Остальные сообщения группы
                 * бот просто игнорирует.
                 */
                return;
            }

            /*
             * ------------------------------------------------
             * ЛИЧНЫЙ ЧАТ
             * ------------------------------------------------
             */

            if (chatType !== 'private') {
                return;
            }

            /*
             * В личке нужен Telegram username.
             */
            if (!tgUsername) {

                await this.send(
                    chatId,
                    `⚠️ У вас не установлен Username в Telegram.

Пожалуйста, укажите @username в настройках Telegram, чтобы сайт смог распознать вас.`
                );

                return;
            }

            /*
             * ------------------------------------------------
             * /start
             * ------------------------------------------------
             *
             * Именно здесь сохраняется ЛИЧНЫЙ chat_id.
             */

            if (
                /^\/start(?:@\w+)?(?:\s+.*)?$/i.test(text)
            ) {

                try {

                    await this.registerPrivateChat(msg);

                    await this.send(
                        chatId,
                        `HomeworkAI

Telegram подтверждён (@${tgUsername}).

Вернитесь на сайт и продолжите регистрацию.

Команда /dz покажет текущее домашнее задание.`
                    );

                } catch (err) {

                    console.error(
                        '[Telegram] Ошибка /start:',
                        err
                    );

                    await this.send(
                        chatId,
                        'Не удалось подтвердить Telegram. Попробуйте ещё раз.'
                    );
                }

                return;
            }

            /*
             * ------------------------------------------------
             * /dz В ЛИЧКЕ
             * ------------------------------------------------
             */

            if (
                /^\/dz(?:@\w+)?$/i.test(text)
            ) {

                try {

                    await this.sendHomework(
                        chatId
                    );

                } catch (err) {

                    console.error(
                        '[Telegram] Ошибка /dz в личке:',
                        err
                    );

                    await this.send(
                        chatId,
                        'Не удалось получить домашнее задание.'
                    );
                }

                return;
            }

            /*
             * Остальные сообщения личного чата
             * бот пока игнорирует.
             */
        }
    };

    /*
     * Используется регистрацией:
     *
     * /api/auth/register/start
     * → telegramSend(private_chat_id, code)
     */
    global.telegramSend = telegram.send.bind(telegram);

    /*
     * ------------------------------------------------
     * WEBHOOK
     * ------------------------------------------------
     */

    app.post(
        webhookPath,
        async (req, res) => {

            const secret =
                req.headers[
                    'x-telegram-bot-api-secret-token'
                ];

            if (
                process.env.TELEGRAM_WEBHOOK_SECRET &&
                secret !==
                process.env.TELEGRAM_WEBHOOK_SECRET
            ) {
                return res.sendStatus(403);
            }

            try {

                await telegram.handle(
                    req.body
                );

                res.sendStatus(200);

            } catch (e) {

                console.error(
                    'Telegram update error:',
                    e
                );

                /*
                 * Telegram лучше всегда получать HTTP 200,
                 * иначе он будет повторно отправлять update.
                 */
                res.sendStatus(200);
            }
        }
    );

    /*
     * ------------------------------------------------
     * РУЧНАЯ НАСТРОЙКА WEBHOOK
     * ------------------------------------------------
     */

    app.get(
        '/api/admin/telegram/setup',
        authRequired,
        roleRequired('admin'),
        async (_req, res) => {

            const base =
                (process.env.APP_URL || '')
                    .replace(/\/+$/, '');

            const url =
                base + webhookPath;

            if (!base) {
                return sendError(
                    res,
                    400,
                    'APP_URL не настроен.'
                );
            }

            try {

                const result =
                    await telegram.call(
                        'setWebhook',
                        {
                            url,
                            secret_token:
                                process.env.TELEGRAM_WEBHOOK_SECRET ||
                                undefined,
                            allowed_updates: [
                                'message'
                            ]
                        }
                    );

                res.json({
                    ok: true,
                    result,
                    url
                });

            } catch (e) {

                sendError(
                    res,
                    500,
                    e.message
                );
            }
        }
    );

} else {

    console.warn(
        '[WARNING] TELEGRAM_BOT_TOKEN не установлен в .env! Бот работать не будет.'
    );
}

/*
 * ------------------------------------------------
 * АВТОМАТИЧЕСКАЯ НАСТРОЙКА WEBHOOK
 * ------------------------------------------------
 */

async function autoSetupTelegramWebhook() {

    if (
        !telegram ||
        !process.env.APP_URL
    ) {
        return;
    }

    const base =
        process.env.APP_URL
            .replace(/\/+$/, '');

    if (!base.startsWith('https://')) {

        console.warn(
            `[Telegram] Внимание: APP_URL равен "${base}". Webhook Telegram требует HTTPS.`
        );

        return;
    }

    const url =
        base + webhookPath;

    try {

        await telegram.call(
            'setWebhook',
            {
                url,
                secret_token:
                    process.env.TELEGRAM_WEBHOOK_SECRET ||
                    undefined,
                allowed_updates: [
                    'message'
                ]
            }
        );

        console.log(
            `[Telegram] Webhook автоматически зарегистрирован: ${url}`
        );

    } catch (err) {

        console.error(
            '[Telegram] Ошибка при авто-регистрации Webhook:',
            err.message
        );
    }
}

/*
 * ------------------------------------------------
 * ОТПРАВКА ДЗ ВО ВСЕ СОХРАНЁННЫЕ ГРУППЫ
 * ------------------------------------------------
 *
 * Сейчас функция просто доступна серверу.
 * Её можно вызвать, например:
 *
 * await telegram.sendHomeworkToAllGroups();
 *
 * Пока сама по расписанию она не вызывается.
 */

function escapeHtmlTelegram(v) {
    return String(v)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
// ---------------- errors + SPA ----------------
app.use((err,_req,res,_next)=>{ console.error(err); sendError(res,500,'Внутренняя ошибка сервера.'); });
app.use('/api',(_req,res)=>sendError(res,404,'API маршрут не найден.'));
app.use((req,res,next)=>{ if(req.method!=='GET') return next(); res.sendFile(path.join(ROOT,'public','index.html')); });

(async()=>{
  await cleanupExpired();
  await seedBase();
  app.listen(PORT, async () => {
    console.log(`HomeworkAI v2 running at http://localhost:${PORT}`);
    await autoSetupTelegramWebhook();
  });
})().catch(err=>{ console.error(err); process.exit(1); });