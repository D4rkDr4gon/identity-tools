// Sample metadata for the SAML metadata inspector. The certificates are
// throwaway self-signed ones generated for this page (example.com names).

export const SAMPLE_IDP = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com/saml" ID="_md-idp-01">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_md-idp-01">
        <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>c2FtcGxlLWRpZ2VzdC12YWx1ZS1ub3QtcmVhbA==</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>c2FtcGxlLXNpZ25hdHVyZS12YWx1ZS1ub3QtcmVhbA==</ds:SignatureValue>
  </ds:Signature>
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
          MIIDIDCCAgigAwIBAgIUR2anJOsj5io95RovE93oVEos5DcwDQYJKoZIhvcNAQELBQAwMDEYMBYG
          A1UEAwwPaWRwLmV4YW1wbGUuY29tMRQwEgYDVQQKDAtFeGFtcGxlIElkUDAeFw0yNjExMTIxNzMy
          MzRaFw0zNjExMDkxNzMyMzRaMDAxGDAWBgNVBAMMD2lkcC5leGFtcGxlLmNvbTEUMBIGA1UECgwL
          RXhhbXBsZSBJZFAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+M8tkurgaGtO83Qc6
          20YaIHK3tN8IfSqAfWfo4FJeRmWbEzJKSEJwH9YH/dB4PxJM+3nLPKW+a8yZxELjbRdJ9viayVqd
          SJyOExetUSGtEJF8NG62wCgY4YgZ+bQ4RZOURKIw9t0bDzNrY3kj7K7W0uwajMxgEE/7ASqXzepj
          AgJdtLczdJnSybWBNFlMOmfLaCGZEcapiblLcPo/F6WCCBlLFsr9C+z/uXIVCFnKMxRZsxep7Dch
          GAh31J8p1qjCAHI/tg3yRnPVz8489R+Xy+nySVgCsAP4sckporfep5L9qxT8SqpA1j0k/IeOrlKL
          unry68XhyMuqdT326apDAgMBAAGjMjAwMB0GA1UdDgQWBBTGjRaEEsVpERO8jautugKvDqYaBDAP
          BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCv8TKybcnsUuTeXGHgYmFCQ2J1rA2l
          +9jC3wjswwFEwjE9khy8D9eztqrbzFdngslUleP5bzU3URvkL9nvr4RoWYIy4Z0YVmAE1/SL41n1
          yeH6ECJOFre/nN9FLGc9eR2GYkgi6Jgpbu11gko+6rRhGFL4Qm7zEVHoA0oZyzlNtS193CEai3kF
          sdTOXrN07aCoBT+m2Eemtzxcs2gzGmdJRauWL/rEJPpZ4zM7frzWxoM7VerJl/JQPoyftH5Vp1ND
          /ce6LvTGtjybc0WwP6Wt8bCT2Cw16Xxklvbqb4KJpq8ADdrNEc9S5+DcUEpUAwRA+cj7po4x3Ker
          n7Wn3lJ8
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/slo"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/sso"/>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" FriendlyName="E-mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" FriendlyName="Given name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
    <saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" FriendlyName="Groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"/>
  </md:IDPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">Example</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">Example Corp</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">https://www.example.com</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:GivenName>Identity Team</md:GivenName>
    <md:EmailAddress>mailto:iam@example.com</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`;

export const SAMPLE_SP = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" entityID="https://app.example.com" validUntil="2036-01-01T00:00:00Z">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo><mdui:DisplayName xml:lang="en">Example App</mdui:DisplayName></mdui:UIInfo>
    </md:Extensions>
    <md:KeyDescriptor>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIC9DCCAdygAwIBAgIUCCzJQ8JxkESks9SS0GXg7Y9v8JQwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAwwPYXBwLmV4YW1wbGUuY29tMB4XDTI2MTExMjE3MzIzNFoXDTM2MTEwOTE3MzIzNFowGjEYMBYGA1UEAwwPYXBwLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7on0tZdHGcet8zdVrCqcIhdBrOwkVwWjpumM/VQN2C4gIXW/2Aa5uEiqYErkOdtDYFb9/fu/WMObxbGqjspqRs9BVr9VXEBLNDqASbjnHIZcRTt2fZ/g5LrEhPim9JUxqCOBbmFCOOs7ZfABLf2VlFX3MSuuL+PJmtjMJ7Tw9uoMZXR+gk62GH2qVldjmWyPJ7KSvJCOX0rhQzEGHvVyp2jkzJvs9LsT0AwU3efX62DNAj4Ty7eSRJdsrkO4S7bpXjyEMPOleQclsXqeJRoWamSW5u/Cn98Z98qJAdhWNL6SrBf6FUAU+voG/Wev2kbaEsrScJUjFSrhFSKLfJzYpQIDAQABozIwMDAdBgNVHQ4EFgQUUsKuGZCEGMMl7+UOgGXP32bXUHgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAnht/vSXEFXQGtMDtaUztgTH2nhJdzCE6tO20esMZX0+AoPrvnr5b2L9sCQQJx9XuKx8THYjEieuec/aQv9WP0hEdqnaLGs6p3KBjKmlXYCK3okig9gr64btDHoDD+D2bnXFIqAlm+xiJXJ1ThI2uBwJx7R4BbmOKw5VefdduNX/8Vq/czKj17gAl/Rdv1CVd/RZxKV/63fKpCcvRWdXlqy8Iw3H/9Hd+fJrtbJr+R/Twb6wcDEOUBH7hrBNnfw6w6AyBjOMjOoYIydd7NONeSzgNowBospuHjFZXyKt3/D1H1qWdWpMNdkvq3zsShwKswwv9TGYguWJEatXwx8NfEA==</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://app.example.com/saml/slo"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:AssertionConsumerService index="0" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://app.example.com/saml/acs"/>
    <md:AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://app.example.com/saml/acs/artifact"/>
    <md:AttributeConsumingService index="0">
      <md:ServiceName xml:lang="en">Example App</md:ServiceName>
      <md:RequestedAttribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" FriendlyName="E-mail" isRequired="true"/>
      <md:RequestedAttribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" FriendlyName="Groups"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:ContactPerson contactType="support">
    <md:Company>Example Corp</md:Company>
    <md:EmailAddress>mailto:support@example.com</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`;
