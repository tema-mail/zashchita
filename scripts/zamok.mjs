// Замок на весь отчёт (порт ~/Sites/ekonomika/scripts/zamok.mjs): body страницы
// со всеми цифрами шифруется PBKDF2-SHA256 (310 000 итераций) → AES-256-GCM, вместо него – форма «Логин / Пароль».
// Браузер расшифровывает у себя. Вход помнится до закрытия вкладки; «Оставаться в системе» по умолчанию выключено –
// иначе логин и пароль лежат в localStorage.
// Креды: ~/.config/zashchita/login, pass. Без них – падаем, чтобы не выложить открытым.
// После замка – проверка: в dist не должно остаться ни одного имени и суммы из данных.
// Второй вход – СВЕРХ админ Артёма (SVERH_LOGIN / SVERH_PASS или ~/.config/sverh-admin/dostup.txt): страница под
// случайным ключом, его копии – под ключом каждого входа; расшифровка – scripts/admin-open.mjs (копия с Milovini).
// Нет СВЕРХ – один вход и предупреждение. Схема – ~/Sites/sverh-admin/docs/zamok-dva-vhoda.md.
//   node scripts/zamok.mjs                         – закрыть свежую сборку dist/index.html
//   node scripts/zamok.mjs --perevyazat <файл>     – уже закрытую страницу (site/index.html) открыть ключом владельца
//                                                    и закрыть заново на все входы, содержимое не меняется
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openBox } from './admin-open.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const ARG = process.argv.indexOf('--perevyazat');
const FILE = ARG > 0 ? path.resolve(process.argv[ARG + 1] || '') : process.env.ZAMOK_FILE || path.join(ROOT, 'dist', 'index.html'); // ZAMOK_FILE – для теста
const DIST = path.dirname(FILE);
const ITER = 310000;

function credentials() {
  const file = (n) => {
    const f = path.join(os.homedir(), '.config', 'zashchita', n);
    return fs.existsSync(f) ? fs.readFileSync(f, 'utf8').trim() : '';
  };
  const login = file('login').trim();
  const pass = file('pass').trim();
  if (!login || pass.length < 16) throw new Error('нет логина или пароль короче 16 знаков (~/.config/zashchita/login, pass)');
  return `${login}\n${pass}`;
}

// СВЕРХ админ: пара или null (как sverhCredentials в admin-crypto.mjs замка админок)
function sverhSecret() {
  let login = (process.env.SVERH_LOGIN || '').trim();
  let pass = (process.env.SVERH_PASS || '').trim();
  const f = path.join(os.homedir(), '.config', 'sverh-admin', 'dostup.txt');
  if ((!login || !pass) && fs.existsSync(f)) {
    const t = fs.readFileSync(f, 'utf8');
    const line = (k) => ((t.match(new RegExp(`^${k}:[ \\t]*(.*)$`, 'm')) || [])[1] || '').trim();
    login = line('логин');
    pass = line('пароль');
  }
  if (!login || pass.length < 12) {
    console.warn('ПРЕДУПРЕЖДЕНИЕ: нет входа СВЕРХ админа (SVERH_LOGIN / SVERH_PASS или ~/.config/sverh-admin/dostup.txt) – страница закрыта одним входом владельца');
    return null;
  }
  return `${login}\n${pass}`;
}

// Коробка v3 (как makeRing + sealRing в admin-crypto.mjs): данные под случайным ключом, его копии – под каждым входом
function sealRing(text, secrets) {
  const b = (x) => x.toString('base64');
  const gcm = (key, iv, buf) => {
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    return Buffer.concat([c.update(buf), c.final(), c.getAuthTag()]); // WebCrypto ждёт тег в конце
  };
  const key = crypto.randomBytes(32);
  const keys = secrets.map((secret) => {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    return { salt: b(salt), iv: b(iv), key: b(gcm(crypto.pbkdf2Sync(secret, salt, ITER, 32, 'sha256'), iv, key)) };
  });
  const iv = crypto.randomBytes(12);
  return { v: 3, iter: ITER, iv: b(iv), data: b(gcm(key, iv, Buffer.from(text, 'utf8'))), keys };
}

const GATE_CSS = `body{margin:0;background:#f9f9f7;font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;color:#0b0b0b}
.login{max-width:380px;margin:12vh auto;background:#fff;border:1px solid #d9dedc;border-radius:16px;padding:28px}
.login h1{margin:0 0 6px;font-size:22px;font-weight:600}.login p{margin:0 0 20px;font-size:14px;color:#6b7472}
.login input{display:block;width:100%;height:46px;padding:0 14px;border:1px solid #d9dedc;border-radius:8px;font:inherit;font-size:16px;margin-bottom:12px;box-sizing:border-box}
.login button{width:100%;height:46px;border:none;border-radius:8px;background:#1c201f;color:#fff;font:inherit;font-weight:600;cursor:pointer}
.login .err{min-height:1.4em;margin:12px 0 0;color:#b3261e;font-size:13px}
.login .keep{display:flex;align-items:center;gap:8px;margin:0 0 14px;font-size:14px;cursor:pointer}
.login .keep input{width:18px;height:18px;margin:0}`;

// openBox – из admin-open.mjs (пара пробуется по всем входам); innerHTML не выполняет <script> – пересоздаём их после расшифровки
const GATE_JS = `(function(){
var K='zs_auth',L='zs_keep',box=JSON.parse(document.getElementById('lock-data').textContent),f=document.getElementById('lock-form'),err=f.querySelector('.err');
var openBox=${openBox.toString()};
async function open(login,pass,quiet,keep){
  try{
    var html=await openBox(box,login,pass);
  }catch(e){try{sessionStorage.removeItem(K);if(quiet)localStorage.removeItem(L)}catch(_){} if(!quiet)err.textContent='Неверный логин или пароль';return}
  var a=JSON.stringify({login:login,pass:pass});
  try{sessionStorage.setItem(K,a);if(keep)localStorage.setItem(L,a)}catch(_){}
  document.body.innerHTML=html;
  document.body.querySelectorAll('script').forEach(function(o){var s=document.createElement('script');for(var i=0;i<o.attributes.length;i++)s.setAttribute(o.attributes[i].name,o.attributes[i].value);s.textContent=o.textContent;o.replaceWith(s)});
}
f.addEventListener('submit',function(e){e.preventDefault();err.textContent='Проверяю…';open(f.login.value.trim(),f.pass.value,false,f.keep.checked)});
try{var a=JSON.parse(sessionStorage.getItem(K)||localStorage.getItem(L)||'null');if(a)open(a.login,a.pass,true,false)}catch(_){}
})();`;

const gate = (box) => `<body><style>${GATE_CSS}</style>
<form class="login" id="lock-form" autocomplete="on"><h1>Стандарт защиты</h1><p>Вход только для владельца</p>
<input name="login" placeholder="Логин" autocomplete="username" required autofocus>
<input name="pass" type="password" placeholder="Пароль" autocomplete="current-password" required>
<label class="keep"><input type="checkbox" name="keep"> Оставаться в системе на этом устройстве</label>
<button type="submit">Войти</button><p class="err" role="status"></p></form>
<script type="application/json" id="lock-data">${JSON.stringify(box)}</script>
<script>${GATE_JS}</script></body>`;

if (!fs.existsSync(FILE)) throw new Error(`нет ${FILE} – сначала сборка`);
const html = fs.readFileSync(FILE, 'utf8');
const locked = html.match(/<script type="application\/json" id="lock-data">([\s\S]*?)<\/script>/);
if (locked && ARG < 0) throw new Error('страница уже закрыта (перевязать на все входы: --perevyazat <файл>)');
if (!locked && ARG > 0) throw new Error('страница не закрыта – перевязывать нечего');
const h = html.indexOf('</head>'), b0 = html.indexOf('<body'), b1 = html.lastIndexOf('</body>');
if (h < 0 || b0 < 0 || b1 < 0) throw new Error('не разобрать страницу');
const owner = credentials();
const secrets = [owner, sverhSecret()].filter((x, i, a) => x && a.indexOf(x) === i);
const headScripts = [];
const head = html.slice(0, h).replace(/<script\b[\s\S]*?<\/script>/g, (m) => (headScripts.push(m), ''));
const inner = locked
  ? await openBox(JSON.parse(locked[1]), owner.slice(0, owner.indexOf('\n')), owner.slice(owner.indexOf('\n') + 1))
  : html.slice(html.indexOf('>', b0) + 1, b1) + headScripts.join('');
fs.writeFileSync(FILE, head + '</head>' + gate(sealRing(inner, secrets)) + html.slice(b1 + '</body>'.length));

// проверка: в выкладке нет ни одного слова отчёта в открытом виде
const probes = ['168.113.179.49', 'Ю-Клуб', 'argon2id', 'ispmanager', 'evolutioncarservice', 'Автобалл', '<article', 'Бегет'];
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
for (const f of walk(DIST)) {
  const text = fs.readFileSync(f, 'utf8');
  const leak = probes.find((p) => text.includes(p));
  if (leak) throw new Error(`утечка в ${path.relative(ROOT, f)}: «${leak}» видно без пароля`);
}
console.log(`Страница закрыта (входов: ${secrets.length}), проверено ${probes.length} строк-проб – открытых данных в dist нет`);
