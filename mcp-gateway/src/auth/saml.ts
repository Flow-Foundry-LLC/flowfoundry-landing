import { SAML } from "@node-saml/node-saml";
import { SignedXml } from "xml-crypto";
import { DOMParser } from "@xmldom/xmldom";

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

const PEM_CERT = `-----BEGIN CERTIFICATE-----\n${CERT}\n-----END CERTIFICATE-----`;

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
  // Signature validation is done manually in validateResponse() below
  // because Zoho includes &#13; entities that break node-saml's c14n.
  wantAssertionsSigned: false,
  wantAuthnResponseSigned: false,
});

export interface SAMLUser {
  email: string;
  nameID: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
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
/**
 * Manually verify XML signature using xml-crypto (handles Zoho's &#13; entities
 * that break node-saml's built-in validation).
 */
function verifyXmlSignature(xml: string): boolean {
  const doc = new DOMParser().parseFromString(xml, "text/xml");

  // Find all Signature elements
  const signatures = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
  if (signatures.length === 0) return false;

  for (let i = 0; i < signatures.length; i++) {
    const sig = new SignedXml();
    sig.publicCert = PEM_CERT;
    sig.loadSignature(signatures[i]!);
    if (!sig.checkSignature(xml)) {
      console.error(`[saml] Signature ${i} validation failed:`, sig.validationErrors);
      return false;
    }
  }
  return true;
}

export async function validateResponse(body: { SAMLResponse: string }): Promise<SAMLUser> {
  // Step 1: Verify XML signature manually (Zoho's &#13; breaks node-saml)
  const xml = Buffer.from(body.SAMLResponse, "base64").toString("utf-8");
  if (!verifyXmlSignature(xml)) {
    throw new Error("SAML signature verification failed");
  }

  // Step 2: Let node-saml parse the profile (with signing checks disabled
  // since we already verified above)
  const { profile } = await saml.validatePostResponseAsync(body);
  if (!profile) throw new Error("SAML validation failed: no profile");

  // Log all profile attributes to discover what Zoho sends
  console.log("[saml] Profile attributes:", JSON.stringify(profile, null, 2));

  // Extract name from common SAML attribute names
  const attrs = profile as Record<string, unknown>;
  const firstName = (attrs["First Name"] || attrs["firstName"] || attrs["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"] || attrs["givenname"] || "") as string;
  const lastName = (attrs["Last Name"] || attrs["lastName"] || attrs["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"] || attrs["surname"] || "") as string;
  const displayName = (attrs["Display Name"] || attrs["displayName"] || attrs["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"] || "") as string;

  return {
    email: profile.nameID || profile.email as string || "",
    nameID: profile.nameID || "",
    firstName,
    lastName,
    displayName,
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
