/**
 * Bit fields of Active Directory attributes, shared by the UAC calculator and
 * the LDAP filter explainer. [bit, name, en, es, risk?]
 */

// [bit, name, en, es, risk] — risk: 'bad' | 'warn' | undefined
export const UAC_FLAGS = [
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

export const GROUP_TYPE_FLAGS = [
  [0x1, 'BUILTIN_LOCAL_GROUP', 'Created by the system', 'Creado por el sistema'],
  [0x2, 'ACCOUNT_GROUP', 'Global scope', 'Ámbito global'],
  [0x4, 'RESOURCE_GROUP', 'Domain local scope', 'Ámbito local de dominio'],
  [0x8, 'UNIVERSAL_GROUP', 'Universal scope', 'Ámbito universal'],
  [0x10, 'APP_BASIC_GROUP', 'Authorization Manager basic group', 'Grupo básico de Authorization Manager'],
  [0x20, 'APP_QUERY_GROUP', 'Authorization Manager query group', 'Grupo de consulta de Authorization Manager'],
  [0x80000000, 'SECURITY_ENABLED', 'Security group (otherwise distribution)', 'Grupo de seguridad (si no, de distribución)'],
];

export const ENCTYPE_FLAGS = [
  [0x1, 'DES-CBC-CRC', 'DES, obsolete', 'DES, obsoleto', 'bad'],
  [0x2, 'DES-CBC-MD5', 'DES, obsolete', 'DES, obsoleto', 'bad'],
  [0x4, 'RC4-HMAC', 'RC4, being retired by Microsoft', 'RC4, en retiro por parte de Microsoft', 'warn'],
  [0x8, 'AES128-CTS-HMAC-SHA1-96', 'AES 128', 'AES 128'],
  [0x10, 'AES256-CTS-HMAC-SHA1-96', 'AES 256', 'AES 256'],
  [0x20, 'AES256-CTS-HMAC-SHA1-96-SK', 'AES 256 session keys', 'Claves de sesión AES 256'],
  [0x80000, 'FAST-supported', 'Kerberos armoring (FAST)', 'Blindaje Kerberos (FAST)'],
  [0x100000, 'Compound-identity-supported', 'Compound identity', 'Identidad compuesta'],
  [0x200000, 'Claims-supported', 'Claims', 'Claims'],
  [0x400000, 'Resource-SID-compression-disabled', 'Resource SID compression disabled', 'Compresión de SID de recurso deshabilitada'],
];

/** value → [{ name, en, es, risk }] plus the bits no flag explains. */
export function decodeBits(flags, value) {
  const v = value >>> 0;
  const set = flags.filter(([bit]) => (v & bit) >>> 0 === bit).map(([bit, name, en, es, risk]) => ({ bit, name, en, es, risk }));
  const known = flags.reduce((acc, [bit]) => (acc | bit) >>> 0, 0);
  return { set, unknown: (v & ~known) >>> 0 };
}
