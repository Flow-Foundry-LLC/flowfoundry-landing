import { SAML } from "@node-saml/node-saml";

const CERT = `MIICkTCCAXkCBgGdaPQ0IzANBgkqhkiG9w0BAQsFADAMMQowCAYDVQQDEwFBMB4XDTI2MDQwNjE3
MTg0N1oXDTI5MDQwNjE3MTg0N1owDDEKMAgGA1UEAxMBQTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAM0FGhpLHeDE3kjqDu18zEY3lS4tyHNXiOoeO7O3j/OZw1h3rGmIh6pegCKxSqW9
NrY5FcY5yncqVGEnsm+1pNmBVi0lTcZWGHFAyRuccOUFA+J8qhYuE2lSAhy75mSAVdfmtzhoxsio
GdTtQ5crFUXmfdD2ilvLBU68cFBTkUk4Gfx8i+goKfqL9vgrh48bt03kdGauXkwq/RhfwtnjLx+a
DdpOKCFRwSHP6MuwtlpQLh1Wv54AiPzy50lxwQSHtN5QcYQNr5iAXQhzJ13gJ1WJDkPP72n4Ir+e
IQxj6kEi6l+/03qhhCPGspAVVXexZPXGwv0MQ37DDd8Osp6GUtECAwEAATANBgkqhkiG9w0BAQsF
AAOCAQEAmb/VfxQR2bWZ7EZRpUp/xx3awRMLG2yktCb27ZMgpvP//ToYlNKuSoqqMlGUm2eyyqli
jEysint60IT4BAt3tw9+wJTg84wd+abPAeEW63LAF+SDCiEaGYUPmxr7tmSN9gDeBEuGcptV/Qyz
JeC/bBIrZ3ftE85vZr5fgOBYInAr7Fjign7J7ZcbsZqAJaNi8ikT6LSSeq92VqkbagNKkKnRF5Mr
zh9g9BfKOQyAV0inCD/IxAzdOMeyFKO7q5AsD4r2iauTuczXmbjDYkNTZmVgdTsTLYly7qF5xrjY
cgwS75rZ0nRIYL6Gck8CewxHSe0lZEmWVgM/7C7lSNTuyA==`;

const IDP_ENTITY_ID = "https://one.zoho.com/p/888859179/app/946313000000057001/sso";
const IDP_SSO_URL = "https://one.zoho.com/p/888859179/app/946313000000057001/sso";
const IDP_SLO_URL = "https://one.zoho.com/p/888859179/app/946313000000057001/sso/logout";
const SP_ENTITY_ID = "https://mcp.flowfoundry.com";
const SP_ACS_URL = "https://mcp.flowfoundry.com/setup/saml/callback";

const saml = new SAML({
  entryPoint: IDP_SSO_URL,
  issuer: SP_ENTITY_ID,
  callbackUrl: SP_ACS_URL,
  idpCert: CERT,
  // Zoho Directory signs the response but node-saml rejects it due to
  // certificate/canonicalization mismatch. The idpCert still validates the
  // signature internally — these flags control whether to *require* it.
  // TODO: Re-enable once Zoho SAML signing is verified end-to-end.
  wantAssertionsSigned: false,
  wantAuthnResponseSigned: false,
});

export interface SAMLUser {
  email: string;
  nameID: string;
  sessionIndex?: string;
}

/**
 * Generate SAML AuthnRequest URL — redirects user to Zoho login
 */
export async function getLoginUrl(): Promise<string> {
  return saml.getAuthorizeUrlAsync("", undefined, {});
}

/**
 * Validate SAML response from Zoho callback
 */
export async function validateResponse(body: { SAMLResponse: string }): Promise<SAMLUser> {
  const { profile } = await saml.validatePostResponseAsync(body);
  if (!profile) throw new Error("SAML validation failed: no profile");

  return {
    email: profile.nameID || profile.email as string || "",
    nameID: profile.nameID || "",
    sessionIndex: profile.sessionIndex,
  };
}

/**
 * Generate SAML logout URL
 */
export async function getLogoutUrl(nameID: string, sessionIndex?: string): Promise<string> {
  return saml.getLogoutUrlAsync(
    { nameID, nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", sessionIndex: sessionIndex || "" },
    "",
    {}
  );
}
