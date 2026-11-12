import { initPage } from './common.js';

initPage({
  _title: 'Identity Tools — utilidades para JWT, SAML y Active Directory',
  h1: 'Herramientas para trabajo de identidades',
  lead: 'Utilidades que uso para diagnosticar SSO, tokens y Active Directory. Se ejecutan por completo en tu navegador: los tokens, assertions y valores que pegás nunca se envían a un servidor.',
  csp: 'Sin backend ni analítica; las conexiones de red están bloqueadas por Content-Security-Policy',
  'jwt.h': 'Decodificador y verificador de JWT',
  'jwt.p': 'Header, claims y ventana de validez de un id_token o access token, con verificación de firma contra un secreto, PEM, certificado o JWKS.',
  'saml.h': 'Decodificador SAML',
  'saml.p': 'SAMLRequest y SAMLResponse de los bindings POST o Redirect: emisor, NameID, condiciones, audiencia, atributos y algoritmos de firma.',
  'md.h': 'Inspector de metadata SAML',
  'md.p': 'Endpoints por binding, formatos de NameID, atributos y certificados de un IdP o SP, con huellas SHA-1 / SHA-256 y vencimiento.',
  'ldap.h': 'Validador y formateador de filtros LDAP',
  'ldap.p': 'Validá, indentá y entendé un filtro: reglas de bits y de grupos anidados, flags de AD, escapado de valores y SID / GUID a binario.',
  'uac.h': 'Calculadora de userAccountControl',
  'uac.p': 'Decodificá o armá los flags de una cuenta de AD, mirá cuáles son un riesgo de seguridad y obtené el filtro LDAP para encontrarlas.',
  'ft.h': 'Conversor de fechas de AD',
  'ft.p': 'FILETIME, Generalized Time y Unix epoch en los dos sentidos, intervalos de AD como maxPwdAge y filtros LDAP para cuentas inactivas.',
  'about.h': 'Sobre estas herramientas',
  'about.1': 'Soy Lucciano Campassi, consultor en gestión y gobernanza de identidades. Más sobre mi trabajo en <a href="/es/"><strong>mi sitio</strong></a>; el código fuente de estas herramientas está en <a href="https://github.com/D4rkDr4gon/identity-tools" rel="noopener"><strong>GitHub</strong></a>.',
});
