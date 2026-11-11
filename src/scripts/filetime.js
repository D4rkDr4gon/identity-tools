import { initPage, esc, fmtDate, fmtLocal, relative } from './common.js';
import { tr } from './i18n.js';

initPage({
  _title: 'Conversor de fechas de AD (FILETIME, LDAP) — Identity Tools',
  h1: 'Conversor de fechas de AD',
  lead: 'Convertí los números que Active Directory guarda en lastLogonTimestamp, pwdLastSet, accountExpires o whenCreated en fechas, y fechas en valores listos para un filtro LDAP.',
  'conv.title': 'Convertir',
  now: 'Ahora',
  'ts.label': 'Valor',
  'ts.hint': 'FILETIME (18 dígitos), Generalized Time (20261111140000.0Z), Unix en segundos o milisegundos, ISO 8601, o un intervalo negativo de AD como maxPwdAge.',
  'stale.title': 'Filtro de cuentas inactivas',
  'days.label': 'Inactivas hace más de (días)',
  'kind.label': 'Objetos',
  'kind.user': 'Usuarios',
  'kind.computer': 'Equipos',
  enabledOnly: 'Solo cuentas habilitadas',
  'about.h': 'Para tener en cuenta',
  'about.1': 'FILETIME cuenta intervalos de 100 nanosegundos desde el 1601-01-01 UTC. <code>0</code> y <code>9223372036854775807</code> son especiales: en <code>accountExpires</code> los dos significan "nunca".',
  'about.2': '<code>lastLogonTimestamp</code> se replica, pero solo se actualiza cuando es más viejo que <code>ms-DS-Logon-Time-Sync-Interval</code> (14 días por defecto menos un aleatorio de hasta 5). Sirve para reportes de cuentas inactivas, no para saber si alguien entró hoy.',
  'about.3': '<code>lastLogon</code> es por controlador de dominio y no se replica: para el valor real hay que consultar todos los DC.',
  'about.4': '<code>pwdLastSet = 0</code> significa que el usuario debe cambiar la contraseña en el próximo inicio de sesión.',
});

const EPOCH_DIFF_MS = 11644473600000n; // 1601-01-01 → 1970-01-01
const NEVER = 9223372036854775807n;

const $ = (id) => document.getElementById(id);
const tsEl = $('ts');

const msToFiletime = (ms) => (BigInt(Math.trunc(ms)) + EPOCH_DIFF_MS) * 10000n;
const filetimeToMs = (ft) => Number(ft / 10000n - EPOCH_DIFF_MS);

function generalized(d) {
  const p = (n, l = 2) => String(n).padStart(l, '0');
  return `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}.0Z`;
}

function duration(ticks) {
  let s = Number(-ticks / 10000000n);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  return [d && `${d} ${tr(d === 1 ? 'day' : 'days', d === 1 ? 'día' : 'días')}`, h && `${h} h`, m && `${m} min`, s && `${s} s`].filter(Boolean).join(' ') || '0 s';
}

/** → { kind, date } | { special } | { interval } | null */
function detect(raw) {
  const s = raw.trim();
  if (!s) return null;

  if (/^-\d+$/.test(s)) return { interval: BigInt(s) };

  const gt = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?(Z|[+-]\d{4})?$/i);
  if (gt) {
    const [, y, mo, d, h, mi, se, tz] = gt;
    const off = tz && tz.toUpperCase() !== 'Z' ? `${tz.slice(0, 3)}:${tz.slice(3)}` : 'Z';
    return { kind: 'Generalized Time', date: new Date(`${y}-${mo}-${d}T${h}:${mi}:${se}${off}`) };
  }

  if (/^\d+$/.test(s)) {
    const n = BigInt(s);
    if (n === 0n) return { special: 'zero' };
    if (n >= NEVER) return { special: 'never' };
    if (s.length >= 15) return { kind: 'FILETIME', date: new Date(filetimeToMs(n)) };
    if (s.length >= 12) return { kind: 'Unix ms', date: new Date(Number(n)) };
    return { kind: 'Unix s', date: new Date(Number(n) * 1000) };
  }

  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? { error: true } : { kind: 'ISO 8601', date: d };
}

function row(k, v, sub = '') {
  return `<tr><th>${esc(k)}</th><td>${esc(v)}${sub ? `<small>${esc(sub)}</small>` : ''}</td></tr>`;
}

function convert() {
  const out = $('convOut');
  const r = detect(tsEl.value);
  if (!r) return (out.innerHTML = '');
  if (r.error) return (out.innerHTML = `<div class="error">${tr('Unrecognised value.', 'Valor no reconocido.')}</div>`);

  if (r.special) {
    const text = r.special === 'zero'
      ? tr('0 = not set. accountExpires: never expires. pwdLastSet: must change password at next logon. lastLogonTimestamp: never logged on.', '0 = sin valor. accountExpires: no vence nunca. pwdLastSet: debe cambiar la contraseña en el próximo inicio. lastLogonTimestamp: nunca inició sesión.')
      : tr('Maximum value (0x7FFFFFFFFFFFFFFF): in accountExpires it means the account never expires.', 'Valor máximo (0x7FFFFFFFFFFFFFFF): en accountExpires significa que la cuenta no vence nunca.');
    return (out.innerHTML = `<h3 class="sub">${tr('Special value', 'Valor especial')}</h3><ul class="notes"><li class="info"><i class="fas fa-circle-info"></i><span>${esc(text)}</span></li></ul>`);
  }

  if (r.interval !== undefined) {
    return (out.innerHTML = `<h3 class="sub">${tr('AD interval', 'Intervalo de AD')}</h3><table class="kv">
      ${row(tr('Duration', 'Duración'), duration(r.interval), tr('Negative 100-ns ticks: maxPwdAge, minPwdAge, lockoutDuration, lockOutObservationWindow…', 'Ticks negativos de 100 ns: maxPwdAge, minPwdAge, lockoutDuration, lockOutObservationWindow…'))}
      ${row(tr('Seconds', 'Segundos'), String(-r.interval / 10000000n))}
    </table>`);
  }

  const d = r.date;
  if (Number.isNaN(d.getTime()) || d.getUTCFullYear() < 1601 || d.getUTCFullYear() > 30828) {
    return (out.innerHTML = `<div class="error">${tr('Out of range.', 'Fuera de rango.')}</div>`);
  }
  const ms = d.getTime();
  out.innerHTML = `<h3 class="sub">${tr('Detected', 'Detectado')}: ${esc(r.kind)}</h3><table class="kv">
    ${row('UTC', fmtDate(d), relative(d))}
    ${row(tr('Local time', 'Hora local'), fmtLocal(d), Intl.DateTimeFormat().resolvedOptions().timeZone)}
    ${row('FILETIME', msToFiletime(ms).toString(), 'lastLogonTimestamp · pwdLastSet · accountExpires · lockoutTime')}
    ${row('Generalized Time', generalized(d), 'whenCreated · whenChanged')}
    ${row('Unix (s)', String(Math.floor(ms / 1000)))}
    ${row('Unix (ms)', String(ms))}
    ${row('ISO 8601', d.toISOString())}
  </table>`;
}

function stale() {
  const days = Math.max(1, Math.min(36500, Number($('days').value) || 90));
  const computer = $('kind').value === 'computer';
  const enabled = $('enabledOnly').checked;
  const cutoff = Date.now() - days * 86400000;
  const ft = msToFiletime(cutoff).toString();
  const cls = computer ? '(objectCategory=computer)' : '(objectCategory=person)(objectClass=user)';
  const notDisabled = enabled ? '(!(userAccountControl:1.2.840.113556.1.4.803:=2))' : '';
  const ldap = `(&${cls}${notDisabled}(lastLogonTimestamp<=${ft}))`;
  const never = `(&${cls}${notDisabled}(!(lastLogonTimestamp=*))(whenCreated<=${generalized(new Date(cutoff))}))`;
  const cmd = computer ? 'Get-ADComputer' : 'Get-ADUser';
  const ps = `${cmd} -LDAPFilter '${ldap}' -Properties lastLogonTimestamp |\n  Select-Object Name, SamAccountName, @{n='LastLogon';e={[DateTime]::FromFileTimeUtc($_.lastLogonTimestamp)}}`;

  $('staleOut').innerHTML = `
    <h3 class="sub">${tr('Cutoff', 'Fecha de corte')}</h3>
    <table class="kv">${row(fmtDate(new Date(cutoff)), ft, 'FILETIME')}</table>
    <h3 class="sub">${tr('LDAP filter: last logon before the cutoff', 'Filtro LDAP: último inicio antes del corte')}</h3>
    <pre class="code" id="ldapStale">${esc(ldap)}</pre>
    <div class="btn-row"><button class="btn" type="button" data-copy="#ldapStale"><i class="fas fa-copy"></i> <span>${tr('Copy', 'Copiar')}</span></button></div>
    <h3 class="sub">${tr('LDAP filter: never logged on, created before the cutoff', 'Filtro LDAP: nunca iniciaron sesión, creadas antes del corte')}</h3>
    <pre class="code" id="ldapNever">${esc(never)}</pre>
    <div class="btn-row"><button class="btn" type="button" data-copy="#ldapNever"><i class="fas fa-copy"></i> <span>${tr('Copy', 'Copiar')}</span></button></div>
    <h3 class="sub">PowerShell</h3>
    <pre class="code" id="psStale">${esc(ps)}</pre>
    <div class="btn-row"><button class="btn" type="button" data-copy="#psStale"><i class="fas fa-copy"></i> <span>${tr('Copy', 'Copiar')}</span></button></div>`;
}

tsEl.addEventListener('input', convert);
$('now').addEventListener('click', () => {
  tsEl.value = msToFiletime(Date.now()).toString();
  convert();
});
['days', 'kind', 'enabledOnly'].forEach((id) => $(id).addEventListener('input', stale));
document.addEventListener('langchange', () => {
  convert();
  stale();
});

tsEl.value = msToFiletime(Date.now()).toString();
convert();
stale();
