// Замок страницы на несколько входов: владелец и СВЕРХ админ открывают, неверная пара – нет; перевязка старой
// страницы (один вход) на все входы без смены содержимого; без СВЕРХ – как раньше. Запуск: node --test scripts/
// Пары выдуманные, настоящие не читаются (HOME подменён на временную папку).
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { openBox } from './admin-open.mjs';

const ZAMOK = path.join(path.dirname(new URL(import.meta.url).pathname), 'zamok.mjs');
const CFG = fs.readFileSync(ZAMOK, 'utf8').match(/'\.config', '([^']+)'/)[1]; // папка кредов владельца этого проекта
const OWNER = { login: 'owner-test', pass: 'owner-test-pass-00001' };
const SVERH = { login: 'sverh-test', pass: 'sverh-test-pass-00002' };
const PAGE = '<html><head><title>a</title><script>window.x=1</script></head><body><h1>Отчёт</h1></body></html>';

function run(env, args = [], page = PAGE) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zamok-'));
  fs.mkdirSync(path.join(home, '.config', CFG), { recursive: true });
  fs.writeFileSync(path.join(home, '.config', CFG, 'login'), OWNER.login);
  fs.writeFileSync(path.join(home, '.config', CFG, 'pass'), OWNER.pass);
  const file = path.join(home, 'site', 'index.html');
  fs.mkdirSync(path.dirname(file));
  fs.writeFileSync(file, page);
  try {
    const out = execFileSync(process.execPath, [ZAMOK, ...args.map((a) => (a === 'FILE' ? file : a))], {
      env: { PATH: process.env.PATH, HOME: home, ZAMOK_FILE: file, ...env }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    });
    const html = fs.readFileSync(file, 'utf8');
    const box = JSON.parse(html.match(/<script type="application\/json" id="lock-data">([\s\S]*?)<\/script>/)[1]);
    return { out, html, box };
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
}
const both = { SVERH_LOGIN: SVERH.login, SVERH_PASS: SVERH.pass };

test('замок с СВЕРХ: открывают владелец и СВЕРХ, неверная пара – нет', async () => {
  const { out, html, box } = run(both);
  assert.match(out, /входов: 2/);
  assert.doesNotMatch(html, /<h1>Отчёт/);
  assert.match(await openBox(box, OWNER.login, OWNER.pass), /<h1>Отчёт<\/h1><script>window\.x=1<\/script>/);
  assert.match(await openBox(box, SVERH.login, SVERH.pass), /<h1>Отчёт/);
  await assert.rejects(openBox(box, SVERH.login, 'неверный-пароль-123'));
});

test('без СВЕРХ – один вход владельца, замок не падает', async () => {
  const { out, box } = run({});
  assert.match(out, /входов: 1/);
  await assert.rejects(openBox(box, SVERH.login, SVERH.pass));
  assert.match(await openBox(box, OWNER.login, OWNER.pass), /<h1>Отчёт/);
});

// страница в старом виде (до двух входов): коробка без v и keys, ключ – прямо из пары владельца
function legacyPage() {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', crypto.pbkdf2Sync(`${OWNER.login}\n${OWNER.pass}`, salt, 310000, 32, 'sha256'), iv);
  const data = Buffer.concat([c.update('<h1>Отчёт</h1><script>window.x=1</script>', 'utf8'), c.final(), c.getAuthTag()]);
  const box = { iter: 310000, salt: salt.toString('base64'), iv: iv.toString('base64'), data: data.toString('base64') };
  return `<html><head><title>a</title></head><body><form id="lock-form"></form><script type="application/json" id="lock-data">${JSON.stringify(box)}</script></body></html>`;
}

test('перевязка: старая страница под одним входом → оба входа, содержимое то же', async () => {
  const old = legacyPage();
  const { out, box } = run(both, ['--perevyazat', 'FILE'], old);
  assert.match(out, /входов: 2/);
  assert.match(await openBox(box, SVERH.login, SVERH.pass), /<h1>Отчёт<\/h1><script>window\.x=1<\/script>/);
  assert.match(await openBox(box, OWNER.login, OWNER.pass), /<h1>Отчёт/);
});

test('уже закрытую страницу без --perevyazat второй раз не закрывает', () => {
  const old = run({}).html;
  assert.throws(() => run(both, [], old));
});
