// Замок на весь отчёт (порт ~/Sites/ekonomika/scripts/zamok.mjs): body страницы
// со всеми цифрами шифруется PBKDF2-SHA256 (310 000 итераций) → AES-256-GCM, вместо него – форма «Логин / Пароль».
// Браузер расшифровывает у себя. Вход помнится до закрытия вкладки; «Оставаться в системе» по умолчанию выключено –
// иначе логин и пароль лежат в localStorage.
// Креды: ~/.config/zashchita/login, pass. Без них – падаем, чтобы не выложить открытым.
// После замка – проверка: в dist не должно остаться ни одного имени и суммы из данных.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const DIST = path.join(ROOT, 'dist');
const FILE = path.join(DIST, 'index.html');
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

function seal(text, secret) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(secret, salt, ITER, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(text, 'utf8'), c.final(), c.getAuthTag()]); // WebCrypto ждёт тег в конце
  const b = (x) => x.toString('base64');
  return { iter: ITER, salt: b(salt), iv: b(iv), data: b(data) };
}

const GATE_CSS = `body{margin:0;background:#f9f9f7;font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;color:#0b0b0b}
.login{max-width:380px;margin:12vh auto;background:#fff;border:1px solid #d9dedc;border-radius:16px;padding:28px}
.login h1{margin:0 0 6px;font-size:22px;font-weight:600}.login p{margin:0 0 20px;font-size:14px;color:#6b7472}
.login input{display:block;width:100%;height:46px;padding:0 14px;border:1px solid #d9dedc;border-radius:8px;font:inherit;font-size:16px;margin-bottom:12px;box-sizing:border-box}
.login button{width:100%;height:46px;border:none;border-radius:8px;background:#1c201f;color:#fff;font:inherit;font-weight:600;cursor:pointer}
.login .err{min-height:1.4em;margin:12px 0 0;color:#b3261e;font-size:13px}
.login .keep{display:flex;align-items:center;gap:8px;margin:0 0 14px;font-size:14px;cursor:pointer}
.login .keep input{width:18px;height:18px;margin:0}`;

// innerHTML не выполняет <script> – пересоздаём их после расшифровки
const GATE_JS = `(function(){
var K='zs_auth',L='zs_keep',box=JSON.parse(document.getElementById('lock-data').textContent),f=document.getElementById('lock-form'),err=f.querySelector('.err');
function b64(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})}
async function open(login,pass,quiet,keep){
  try{
    var base=await crypto.subtle.importKey('raw',new TextEncoder().encode(login+'\\n'+pass),'PBKDF2',false,['deriveKey']);
    var key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:b64(box.salt),iterations:box.iter},base,{name:'AES-GCM',length:256},false,['decrypt']);
    var html=new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(box.iv)},key,b64(box.data)));
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

if (!fs.existsSync(FILE)) throw new Error('нет dist/index.html – сначала сборка');
const html = fs.readFileSync(FILE, 'utf8');
if (html.includes('id="lock-data"')) throw new Error('страница уже закрыта');
const h = html.indexOf('</head>'), b0 = html.indexOf('<body'), b1 = html.lastIndexOf('</body>');
if (h < 0 || b0 < 0 || b1 < 0) throw new Error('не разобрать страницу');
const headScripts = [];
const head = html.slice(0, h).replace(/<script\b[\s\S]*?<\/script>/g, (m) => (headScripts.push(m), ''));
const inner = html.slice(html.indexOf('>', b0) + 1, b1) + headScripts.join('');
fs.writeFileSync(FILE, head + '</head>' + gate(seal(inner, credentials())) + html.slice(b1 + '</body>'.length));

// проверка: в выкладке нет ни одного слова отчёта в открытом виде
const probes = ['168.113.179.49', 'Ю-Клуб', 'argon2id', 'ispmanager', 'evolutioncarservice', 'Автобалл', '<article', 'Бегет'];
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
for (const f of walk(DIST)) {
  const text = fs.readFileSync(f, 'utf8');
  const leak = probes.find((p) => text.includes(p));
  if (leak) throw new Error(`утечка в ${path.relative(ROOT, f)}: «${leak}» видно без пароля`);
}
console.log(`Страница закрыта, проверено ${probes.length} строк-проб – открытых данных в dist нет`);
