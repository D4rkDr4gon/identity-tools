import { initPage, esc } from './common.js';
import { tr } from './i18n.js';

initPage({
  _title: 'Calculadora de userAccountControl — Identity Tools',
  h1: 'Calculadora de userAccountControl',
  lead: 'Escribí un valor para ver qué flags tiene, o marcá flags para armarlo. También te da el filtro LDAP y la consulta de PowerShell para encontrar cuentas con esos bits.',
  'value.title': 'Valor',
  'value.label': 'userAccountControl (decimal o hex con 0x)',
  'flags.title': 'Flags',
  'query.title': 'Buscar cuentas con estos flags',
  'about.h': 'Para tener en cuenta',
  'about.1': '<code>LOCKOUT</code> y <code>PASSWORD_EXPIRED</code> no se mantienen actualizados en <code>userAccountControl</code>. Consultá <code>msDS-User-Account-Control-Computed</code> o <code>lockoutTime</code> / <code>pwdLastSet</code>.',
  'about.2': '<code>PASSWD_CANT_CHANGE</code> se aplica con un ACE sobre el objeto, no con este bit: marcarlo solo no hace nada.',
  'about.3': 'El OID <code>1.2.840.113556.1.4.803</code> es la regla de coincidencia AND a nivel de bits (deben estar todos); <code>1.2.840.113556.1.4.804</code> es OR (alcanza con uno).',
});

// [bit, name, en, es, risk] — risk: 'bad' | 'warn' | undefined
const FLAGS = [
  [0x1, 'SCRIPT', 'Logon script runs', 'Se ejecuta el script de inicio de sesión'],
  [0x2, 'ACCOUNTDISABLE', 'Account disabled', 'Cuenta deshabilitada'],
  [0x8, 'HOMEDIR_REQUIRED', 'Home folder required', 'Requiere carpeta personal'],
  [0x10, 'LOCKOUT', 'Locked out (not reliable here)', 'Bloqueada (no confiable acá)'],
  [0x20, 'PASSWD_NOTREQD', 'Password not required', 'No requiere contraseña', 'bad'],
  [0x40, 'PASSWD_CANT_CHANGE', 'User cannot change password (ACE-based)', 'El usuario no puede cambiar la contraseña (por ACE)'],
  [0x80, 'ENCRYPTED_TEXT_PWD_ALLOWED', 'Reversible password encryption', 'Contraseña con cifrado reversible', 'bad'],
  [0x100, 'TEMP_DUPLICATE_ACCOUNT', 'Local account for users from another domain', 'Cuenta local para usuarios de otro dominio'],
  [0x200, 'NORMAL_ACCOUNT', 'Normal user account', 'Cuenta de usuario normal'],
  [0x800, 'INTERDOMAIN_TRUST_ACCOUNT', 'Trust account for a domain that trusts others', 'Cuenta de confianza entre dominios'],
  [0x1000, 'WORKSTATION_TRUST_ACCOUNT', 'Computer account (workstation or member server)', 'Cuenta de equipo (estación o servidor miembro)'],
  [0x2000, 'SERVER_TRUST_ACCOUNT', 'Domain controller computer account', 'Cuenta de equipo de un controlador de dominio'],
  [0x10000, 'DONT_EXPIRE_PASSWORD', 'Password never expires', 'La contraseña nunca vence', 'warn'],
  [0x20000, 'MNS_LOGON_ACCOUNT', 'MNS logon account', 'Cuenta de inicio de sesión MNS'],
  [0x40000, 'SMARTCARD_REQUIRED', 'Smart card required for interactive logon', 'Requiere tarjeta inteligente para el inicio interactivo'],
  [0x80000, 'TRUSTED_FOR_DELEGATION', 'Unconstrained Kerberos delegation', 'Delegación Kerberos sin restricciones', 'bad'],
  [0x100000, 'NOT_DELEGATED', 'Sensitive, cannot be delegated', 'Sensible, no se puede delegar'],
  [0x200000, 'USE_DES_KEY_ONLY', 'Kerberos DES only', 'Kerberos solo con DES', 'bad'],
  [0x400000, 'DONT_REQ_PREAUTH', 'No Kerberos pre-authentication (AS-REP roastable)', 'Sin preautenticación Kerberos (vulnerable a AS-REP roasting)', 'bad'],
  [0x800000, 'PASSWORD_EXPIRED', 'Password expired (not reliable here)', 'Contraseña vencida (no confiable acá)'],
  [0x1000000, 'TRUSTED_TO_AUTH_FOR_DELEGATION', 'Constrained delegation with protocol transition', 'Delegación restringida con transición de protocolo', 'warn'],
  [0x4000000, 'PARTIAL_SECRETS_ACCOUNT', 'Read-only domain controller (RODC)', 'Controlador de dominio de solo lectura (RODC)'],
];
const KNOWN = FLAGS.reduce((acc, [bit]) => acc | bit, 0);

const PRESETS = [
  [512, ['Enabled user', 'Usuario habilitado']],
  [514, ['Disabled user', 'Usuario deshabilitado']],
  [66048, ['Password never expires', 'Contraseña sin vencimiento']],
  [66050, ['Disabled, never expires', 'Deshabilitado, sin vencimiento']],
  [544, ['Password not required', 'Sin contraseña requerida']],
  [4096, ['Computer', 'Equipo']],
  [532480, ['Domain controller', 'Controlador de dominio']],
];

const $ = (id) => document.getElementById(id);
const valueEl = $('value');
let value = 512;

function parseValue(raw) {
  const s = raw.trim().toLowerCase();
  if (!s) return 0;
  const n = s.startsWith('0x') ? parseInt(s.slice(2), 16) : /^\d+$/.test(s) ? parseInt(s, 10) : NaN;
  return Number.isFinite(n) && n >= 0 && n <= 0xffffffff ? n : null;
}

const hex = (n) => `0x${n.toString(16).toUpperCase().padStart(8, '0')}`;

function renderPresets() {
  $('presets').innerHTML = PRESETS.map(
    ([v, [en, es]]) => `<button class="btn" type="button" data-preset="${v}" title="${esc(tr(en, es))}">${v} · ${esc(tr(en, es))}</button>`,
  ).join('');
}

function renderFlags() {
  $('flags').innerHTML = FLAGS.map(([bit, name, en, es, risk]) => {
    const on = (value & bit) !== 0;
    return `<label class="flag${on ? ' on' : ''}">
      <input type="checkbox" data-bit="${bit}"${on ? ' checked' : ''} />
      <span><span class="flag-name">${name}${risk === 'bad' ? ' <i class="fas fa-triangle-exclamation risk"></i>' : ''}</span>
      <span class="flag-meta"><code>${bit} · ${hex(bit)}</code> — ${esc(tr(en, es))}</span></span>
    </label>`;
  }).join('');
}

function renderSummary() {
  $('big').innerHTML = `<strong>${value}</strong><span>${hex(value)}</span><span>${value.toString(2)}b</span>`;

  const notes = [];
  const add = (level, en, es) => notes.push(`<li class="${level}"><i class="fas ${level === 'bad' ? 'fa-circle-xmark' : level === 'warn' ? 'fa-triangle-exclamation' : level === 'ok' ? 'fa-circle-check' : 'fa-circle-info'}"></i><span>${esc(tr(en, es))}</span></li>`);
  const has = (bit) => (value & bit) !== 0;

  const unknown = value & ~KNOWN;
  if (unknown) add('warn', `Bits not defined by Microsoft: ${hex(unknown >>> 0)}.`, `Bits no definidos por Microsoft: ${hex(unknown >>> 0)}.`);

  const types = [0x200, 0x800, 0x1000, 0x2000, 0x100].filter(has);
  if (!types.length && value) add('warn', 'No account type bit (NORMAL_ACCOUNT, WORKSTATION_TRUST_ACCOUNT…). AD rejects that combination.', 'No tiene bit de tipo de cuenta (NORMAL_ACCOUNT, WORKSTATION_TRUST_ACCOUNT…). AD rechaza esa combinación.');
  if (types.length > 1) add('warn', 'More than one account type bit set.', 'Tiene más de un bit de tipo de cuenta.');

  if (has(0x2)) add('info', 'Disabled: the account cannot log on.', 'Deshabilitada: la cuenta no puede iniciar sesión.');
  if (has(0x20)) add('bad', 'PASSWD_NOTREQD: the account may have an empty password, regardless of the domain policy.', 'PASSWD_NOTREQD: la cuenta puede tener contraseña vacía, más allá de la política del dominio.');
  if (has(0x80)) add('bad', 'Reversible encryption: the password is stored in a recoverable form.', 'Cifrado reversible: la contraseña se guarda de forma recuperable.');
  if (has(0x400000)) add('bad', 'No Kerberos pre-auth: anyone can request an AS-REP and crack it offline.', 'Sin preautenticación Kerberos: cualquiera puede pedir un AS-REP y crackearlo offline.');
  if (has(0x80000) && !has(0x2000)) add('bad', 'Unconstrained delegation on a non-DC: TGTs of every user who connects are cached on it.', 'Delegación sin restricciones fuera de un DC: guarda en caché los TGT de cada usuario que se conecta.');
  if (has(0x200000)) add('bad', 'DES-only Kerberos is obsolete and disabled by default since Windows 7 / 2008 R2.', 'Kerberos solo DES es obsoleto y está deshabilitado por defecto desde Windows 7 / 2008 R2.');
  if (has(0x1000000)) add('warn', 'Protocol transition: the service can obtain tickets for any user to its allowed targets without their password.', 'Transición de protocolo: el servicio puede obtener tickets de cualquier usuario hacia sus destinos permitidos sin su contraseña.');
  if (has(0x10000) && has(0x200)) add('warn', 'Password never expires: acceptable for some service accounts, but review who owns it.', 'La contraseña nunca vence: aceptable en algunas cuentas de servicio, pero revisá quién es el responsable.');
  if (has(0x10) || has(0x800000)) add('info', 'LOCKOUT / PASSWORD_EXPIRED are computed: read msDS-User-Account-Control-Computed.', 'LOCKOUT / PASSWORD_EXPIRED son calculados: leé msDS-User-Account-Control-Computed.');
  if (!notes.length) add('ok', 'Nothing unusual in this value.', 'Nada fuera de lo común en este valor.');

  $('notes').innerHTML = notes.join('');
}

function renderQuery() {
  const set = FLAGS.filter(([bit]) => value & bit);
  if (!set.length) {
    $('query').innerHTML = `<p class="empty">${tr('Select at least one flag.', 'Elegí al menos un flag.')}</p>`;
    return;
  }
  const computer = (value & (0x1000 | 0x2000)) !== 0;
  const cls = computer ? '(objectCategory=computer)' : '(objectCategory=person)(objectClass=user)';
  // Account-type bits are part of the value; matching on them is fine with the AND rule.
  const ldap = `(&${cls}(userAccountControl:1.2.840.113556.1.4.803:=${value}))`;
  const cmd = computer ? 'Get-ADComputer' : 'Get-ADUser';
  const ps = `${cmd} -LDAPFilter '${ldap}' -Properties userAccountControl | Select-Object Name, SamAccountName, userAccountControl`;
  $('query').innerHTML = `
    <label>${tr('LDAP filter (all selected bits set)', 'Filtro LDAP (todos los bits seleccionados)')}</label>
    <pre class="code" id="ldapOut">${esc(ldap)}</pre>
    <div class="btn-row"><button class="btn" type="button" data-copy="#ldapOut"><i class="fas fa-copy"></i> <span>${tr('Copy', 'Copiar')}</span></button></div>
    <h3 class="sub">PowerShell (${tr('ActiveDirectory module', 'módulo ActiveDirectory')})</h3>
    <pre class="code" id="psOut">${esc(ps)}</pre>
    <div class="btn-row"><button class="btn" type="button" data-copy="#psOut"><i class="fas fa-copy"></i> <span>${tr('Copy', 'Copiar')}</span></button></div>
    <p class="hint">${esc(tr(
      'Tip: to search for a single risky bit (e.g. 4194304 for DONT_REQ_PREAUTH), select only that flag.',
      'Tip: para buscar un solo bit riesgoso (p. ej. 4194304 para DONT_REQ_PREAUTH), dejá marcado solo ese flag.',
    ))}</p>`;
}

function renderAll() {
  renderPresets();
  renderFlags();
  renderSummary();
  renderQuery();
}

function setValue(v, fromInput = false) {
  value = v >>> 0;
  if (!fromInput) valueEl.value = String(value);
  renderFlags();
  renderSummary();
  renderQuery();
}

valueEl.addEventListener('input', () => {
  const v = parseValue(valueEl.value);
  valueEl.setAttribute('aria-invalid', v === null ? 'true' : 'false');
  if (v !== null) setValue(v, true);
});
$('flags').addEventListener('change', (e) => {
  const bit = Number(e.target.dataset.bit);
  if (!bit) return;
  setValue(e.target.checked ? value | bit : value & ~bit);
});
$('presets').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-preset]');
  if (btn) setValue(Number(btn.dataset.preset));
});
document.addEventListener('langchange', renderAll);

const initial = parseValue(new URLSearchParams(location.search).get('v') || '');
if (initial) setValue(initial);
renderAll();
