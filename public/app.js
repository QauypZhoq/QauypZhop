'use strict';
const T = {
  kk: {
    h1: 'Сайттың қауіпсіздігін тексеріңіз',
    lead: 'Сайт мекенжайын енгізіңіз — HTTPS, қауіпсіздік тақырыптары, cookie және электрондық пошта қорғанысын тексеріп, баға береміз.',
    ph: 'example.kz', btn: 'Тексеру', busy: 'Тексерілуде…',
    note: 'Тек жалпыға қолжетімді деректер оқылады: ешқандай шабуыл немесе осалдықты пайдалану жасалмайды.',
    foot: 'Нәтиже сайттың бүгінгі ашық параметрлерін көрсетеді және толық қауіпсіздік аудитін алмастырмайды.',
    err_invalid: 'Мекенжай дұрыс емес. Мысалы: example.kz',
    err_blocked: 'Бұл мекенжайды тексеруге болмайды (ішкі немесе жабық желі).',
    err_unreachable: 'Сайтқа қосыла алмадық. Мекенжайды тексеріп, қайта көріңіз.',
    err_rate: 'Сұраныс тым көп. Бір минуттан кейін қайталаңыз.',
    err_generic: 'Қате кетті. Кейінірек қайталаңыз.',
    score: 'Қорытынды балл', pass: 'Өтті', warn: 'Ескерту', fail: 'Өтпеді', fix: 'Түзету жолы', days: 'күн',
    c: {
      tls_valid: ['HTTPS сертификаты жарамды', 'Сенімді орталықтан (мысалы, Let\'s Encrypt) жарамды сертификат орнатыңыз.'],
      tls_version: ['TLS нұсқасы', 'Серверде TLS 1.3 қосып, TLS 1.1 және одан төмен нұсқаларды өшіріңіз.'],
      tls_expiry: ['Сертификат мерзімі', 'Сертификатты мерзімі біткенге дейін жаңартыңыз, автоматты жаңартуды қосыңыз.'],
      https_redirect: ['HTTP → HTTPS бағыттау', '80-порттағы барлық сұранысты https:// мекенжайына бағыттаңыз.'],
      hsts: ['HSTS (Strict-Transport-Security)', 'Strict-Transport-Security: max-age=31536000; includeSubDomains тақырыбын қосыңыз.'],
      csp: ['Content-Security-Policy', 'CSP тақырыбын қосып, unsafe-inline және unsafe-eval мәндерінен аулақ болыңыз.'],
      xfo: ['Clickjacking қорғанысы', 'X-Frame-Options: DENY немесе CSP ішінде frame-ancestors қосыңыз.'],
      xcto: ['X-Content-Type-Options', 'X-Content-Type-Options: nosniff тақырыбын қосыңыз.'],
      referrer: ['Referrer-Policy', 'Referrer-Policy: strict-origin-when-cross-origin тақырыбын қосыңыз.'],
      permissions: ['Permissions-Policy', 'Камера, геолокация сияқты қажетсіз мүмкіндіктерді Permissions-Policy арқылы өшіріңіз.'],
      cookies: ['Cookie қауіпсіздігі', 'Cookie файлдарына Secure, HttpOnly және SameSite белгілерін қосыңыз.'],
      server_leak: ['Сервер нұсқасын ашып көрсету', 'Server және X-Powered-By тақырыптарындағы нұсқа ақпаратын жасырыңыз.'],
      spf: ['SPF жазбасы', 'Домен үшін v=spf1 ... -all түріндегі TXT жазбасын қосыңыз.'],
      dmarc: ['DMARC жазбасы', '_dmarc TXT жазбасын p=quarantine немесе p=reject мәнімен қосыңыз.'],
      caa: ['CAA жазбасы', 'Сертификат бере алатын орталықтарды CAA DNS жазбасымен шектеңіз.'],
      security_txt: ['security.txt файлы', '/.well-known/security.txt файлын қосып, осалдық туралы хабарлау байланысын көрсетіңіз.']
    }
  },
  ru: {
    h1: 'Проверка безопасности сайта',
    lead: 'Введите адрес сайта — мы проверим HTTPS, заголовки безопасности, cookie и защиту почты и выставим оценку.',
    ph: 'example.kz', btn: 'Проверить', busy: 'Проверяем…',
    note: 'Читаются только публичные данные: никаких атак и эксплуатации уязвимостей.',
    foot: 'Результат отражает открытые настройки сайта на сегодня и не заменяет полноценный аудит безопасности.',
    err_invalid: 'Некорректный адрес. Пример: example.kz',
    err_blocked: 'Этот адрес проверить нельзя (внутренняя или закрытая сеть).',
    err_unreachable: 'Не удалось подключиться к сайту. Проверьте адрес и повторите.',
    err_rate: 'Слишком много запросов. Повторите через минуту.',
    err_generic: 'Что-то пошло не так. Повторите позже.',
    score: 'Итоговый балл', pass: 'Пройдено', warn: 'Предупреждение', fail: 'Не пройдено', fix: 'Как исправить', days: 'дн.',
    c: {
      tls_valid: ['Действительный HTTPS-сертификат', 'Установите действительный сертификат от доверенного центра, например Let\'s Encrypt.'],
      tls_version: ['Версия TLS', 'Включите TLS 1.3 и отключите TLS 1.1 и ниже.'],
      tls_expiry: ['Срок действия сертификата', 'Продлевайте сертификат заранее и включите автоматическое продление.'],
      https_redirect: ['Перенаправление HTTP → HTTPS', 'Перенаправляйте все запросы с порта 80 на https://.'],
      hsts: ['HSTS (Strict-Transport-Security)', 'Добавьте заголовок Strict-Transport-Security: max-age=31536000; includeSubDomains.'],
      csp: ['Content-Security-Policy', 'Добавьте заголовок CSP и избегайте значений unsafe-inline и unsafe-eval.'],
      xfo: ['Защита от clickjacking', 'Добавьте X-Frame-Options: DENY или директиву frame-ancestors в CSP.'],
      xcto: ['X-Content-Type-Options', 'Добавьте заголовок X-Content-Type-Options: nosniff.'],
      referrer: ['Referrer-Policy', 'Добавьте заголовок Referrer-Policy: strict-origin-when-cross-origin.'],
      permissions: ['Permissions-Policy', 'Отключите ненужные возможности (камера, геолокация) через Permissions-Policy.'],
      cookies: ['Безопасность cookie', 'Добавьте cookie флаги Secure, HttpOnly и SameSite.'],
      server_leak: ['Раскрытие версии сервера', 'Скройте информацию о версиях в заголовках Server и X-Powered-By.'],
      spf: ['Запись SPF', 'Добавьте для домена TXT-запись вида v=spf1 ... -all.'],
      dmarc: ['Запись DMARC', 'Добавьте TXT-запись _dmarc со значением p=quarantine или p=reject.'],
      caa: ['Запись CAA', 'Ограничьте центры, выдающие сертификаты, записью CAA в DNS.'],
      security_txt: ['Файл security.txt', 'Добавьте /.well-known/security.txt с контактом для сообщений об уязвимостях.']
    }
  },
  en: {
    h1: 'Check a website\'s security',
    lead: 'Enter a website address. We check HTTPS, security headers, cookies and email protection, then give it a grade.',
    ph: 'example.com', btn: 'Check', busy: 'Checking…',
    note: 'Only public data is read: no attacks and no exploitation of vulnerabilities.',
    foot: 'The result reflects the site\'s public settings today and does not replace a full security audit.',
    err_invalid: 'Invalid address. Example: example.com',
    err_blocked: 'This address cannot be checked (internal or private network).',
    err_unreachable: 'Could not connect to the site. Check the address and try again.',
    err_rate: 'Too many requests. Try again in a minute.',
    err_generic: 'Something went wrong. Try again later.',
    score: 'Total score', pass: 'Passed', warn: 'Warning', fail: 'Failed', fix: 'How to fix', days: 'days',
    c: {
      tls_valid: ['Valid HTTPS certificate', 'Install a valid certificate from a trusted authority, for example Let\'s Encrypt.'],
      tls_version: ['TLS version', 'Enable TLS 1.3 and disable TLS 1.1 and older.'],
      tls_expiry: ['Certificate expiry', 'Renew the certificate well before it expires and enable automatic renewal.'],
      https_redirect: ['HTTP → HTTPS redirect', 'Redirect every request on port 80 to https://.'],
      hsts: ['HSTS (Strict-Transport-Security)', 'Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains.'],
      csp: ['Content-Security-Policy', 'Add a CSP header and avoid the unsafe-inline and unsafe-eval values.'],
      xfo: ['Clickjacking protection', 'Add X-Frame-Options: DENY or the frame-ancestors directive in CSP.'],
      xcto: ['X-Content-Type-Options', 'Add the header X-Content-Type-Options: nosniff.'],
      referrer: ['Referrer-Policy', 'Add the header Referrer-Policy: strict-origin-when-cross-origin.'],
      permissions: ['Permissions-Policy', 'Turn off unneeded features (camera, geolocation) with Permissions-Policy.'],
      cookies: ['Cookie security', 'Set the Secure, HttpOnly and SameSite flags on cookies.'],
      server_leak: ['Server version disclosure', 'Hide version details in the Server and X-Powered-By headers.'],
      spf: ['SPF record', 'Add a TXT record like v=spf1 ... -all for the domain.'],
      dmarc: ['DMARC record', 'Add a _dmarc TXT record with p=quarantine or p=reject.'],
      caa: ['CAA record', 'Limit which authorities may issue certificates with a CAA DNS record.'],
      security_txt: ['security.txt file', 'Add /.well-known/security.txt with a contact for vulnerability reports.']
    }
  }
};

const $ = s => document.querySelector(s);
let lang = 'kk', data = null, errCode = null;
try { const s = localStorage.getItem('lang'); if (T[s]) lang = s; } catch {}

const t = k => T[lang][k] ?? T.en[k] ?? k;
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text; // textContent only: remote header values are untrusted
  return e;
}

function render(d) {
  const root = $('#result');
  root.replaceChildren();
  const g = el('div', 'grade', d.grade);
  g.dataset.g = d.grade;
  const info = el('div');
  info.append(
    el('div', 'score', `${t('score')}: ${d.score}/100`),
    el('div', 'host', d.host + (d.finalHost && d.finalHost !== d.host ? ` → ${d.finalHost}` : ''))
  );
  const sum = el('div', 'sum');
  sum.append(g, info);

  const order = { fail: 0, warn: 1, pass: 2 };
  const ul = el('ul', 'list');
  [...d.checks].sort((a, b) => order[a.status] - order[b.status]).forEach(c => {
    const [name, fix] = T[lang].c[c.id];
    const li = el('li', 'item ' + c.status);
    const ic = el('span', 'ic', { pass: '✓', warn: '!', fail: '✕' }[c.status]);
    ic.setAttribute('aria-hidden', 'true');
    const body = el('div', 'body');
    const head = el('div', 'head');
    head.append(el('strong', '', name), el('span', 'st', t(c.status)));
    body.append(head);
    if (c.data) body.append(el('code', '', c.id === 'tls_expiry' ? `${c.data} ${t('days')}` : c.data));
    if (c.status !== 'pass') body.append(el('p', 'fix', `${t('fix')}: ${fix}`));
    li.append(ic, body);
    ul.append(li);
  });
  root.append(sum, ul);
}

function showMsg() {
  const m = $('#msg');
  m.textContent = errCode ? t('err_' + errCode) : '';
  m.className = 'msg' + (errCode ? ' err' : '');
}

function applyLang() {
  document.documentElement.lang = lang;
  document.title = 'Қалқан — ' + t('h1');
  document.querySelectorAll('[data-i18n]').forEach(e => { e.textContent = t(e.dataset.i18n); });
  $('#url').placeholder = t('ph');
  document.querySelectorAll('.lang button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.l === lang)));
  showMsg();
  if (data) render(data);
}

document.querySelectorAll('.lang button').forEach(b => b.addEventListener('click', () => {
  lang = b.dataset.l;
  try { localStorage.setItem('lang', lang); } catch {}
  applyLang();
}));

$('form').addEventListener('submit', async e => {
  e.preventDefault();
  const v = $('#url').value.trim();
  if (!v) return;
  const btn = $('.go');
  btn.disabled = true;
  errCode = null;
  $('#msg').className = 'msg';
  $('#msg').textContent = t('busy');
  data = null;
  $('#result').replaceChildren();
  try {
    const res = await fetch('/api/scan?url=' + encodeURIComponent(v));
    const j = await res.json();
    if (j.error) errCode = j.error; else data = j;
  } catch { errCode = 'generic'; }
  btn.disabled = false;
  showMsg();
  if (data) render(data);
});

applyLang();
