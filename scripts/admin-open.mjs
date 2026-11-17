// Расшифровка замка в браузере (и в тестах на node – тот же код). Без node-модулей: lock-admin.mjs вставляет
// эту функцию в форму входа как текст (openBox.toString()), кабинеты с данными могут импортировать её напрямую.
// Коробка v3 (несколько входов): данные зашифрованы случайным ключом страницы, а ключ – копиями, завёрнутыми
// ключом каждого входа (владелец сайта, СВЕРХ админ): PBKDF2-SHA256 «логин\nпароль» → AES-256-GCM.
// Пара пробуется по всем копиям. Коробка v2 (старая, один вход) – ключ входа сразу открывает данные.
// Копия одна на все проекты с замком – правка здесь = правка во всех (~/Sites/sverh-admin/docs/zamok-dva-vhoda.md).
export async function openBox(box, login, pass) {
  var b64 = function (s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); };
  var base = await crypto.subtle.importKey('raw', new TextEncoder().encode(login + '\n' + pass), 'PBKDF2', false, ['deriveKey']);
  var kek = function (salt) {
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(salt), iterations: box.iter }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  };
  var key = null;
  if (box.keys) {
    for (var i = 0; i < box.keys.length && !key; i++) {
      try {
        var w = box.keys[i];
        var raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(w.iv) }, await kek(w.salt), b64(w.key));
        key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
      } catch (e) {}
    }
    if (!key) throw new Error('неверный логин или пароль');
  } else key = await kek(box.salt);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(box.iv) }, key, b64(box.data)));
}
