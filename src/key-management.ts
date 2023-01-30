import * as jose from "node-jose";
import * as logger from "checkout-logger";
import {DspPrivateKeys, httpGetJson} from "./utils";
import assert = require("assert");

interface JwksData {
    readonly keys:  ReadonlyArray<JwksKey>;
    readonly iss: string;
    readonly sub: string;
    readonly iat: number;
    readonly exp: number;
}

interface JwksKey {
    readonly kty?: string;
    readonly kid?: string;
    readonly use?: string;
    readonly n?: string;
    readonly e?: string;
    readonly [key: string]: any;
}

interface JwksKeys {
    readonly keys: ReadonlyArray<JwksKey>;
}

const ENTITY_EXP_TIME = 10 * 365 * 24 * 60 * 60; // 3650 days ~ 10 years
const JWKS_EXP_TIME = 90000; // 25 hours
export const SIGN_ALGS = ["RS256"];

/**
 * Get JWKS for the OIDC SP
* @param {DspPrivateKeys} privateKeys DSP keys
* @param {LogSpan} logSpan optional Log instance
* @return {Promise<JwksKey} SP's JWKS JSON object
 */
export async function getJwks(
    privateKeys: DspPrivateKeys,
    logSpan?: logger.LogSpan
): Promise<JwksKeys> {

    const log = logSpan || new logger.LogSpan();
    const keyStore = jose.JWK.createKeyStore();
    try {
        await keyStore.add(privateKeys.signingKey, "pem", {use: "sig"});
        await keyStore.add(privateKeys.encyptionKey, "pem", {use: "enc"});
        return keyStore.toJSON();
    } catch (error) {
        log.error("dsp.jwks.error", <string>error.message,
            logger.LogGroup.Technical, undefined
        );
        return {keys: []};
    }
}

/**
 * Get signed JWKS for the OIDC SP
* @param {DspPrivateKeys} privateKeys DSP keys
* @param {string} host DSP hostname
* @param {LogSpan} logSpan optional Log instance
* @return {Promise<string} Signed JSON web token containing the JWKS of the SP
 */
export async function getSignedJwks(
    privateKeys: DspPrivateKeys,
    host: string,
    logSpan?: logger.LogSpan
): Promise<string> {

    const log = logSpan || new logger.LogSpan();
    try {
        const now = Math.floor(Date.now() / 1000);
        const jwksToSign: JwksData = {
            keys:  (await getJwks(privateKeys)).keys,
            iss: `https://${host}`,
            sub: `https://${host}`,
            iat: now,
            exp: now + JWKS_EXP_TIME
        };

        const jwksJsonString = JSON.stringify(jwksToSign);
        const signingKey = await jose.JWK.asKey(privateKeys.entityKey, "pem");
        return await  jose.JWS.createSign(
            { fields: {alg: "RS256"}, format: "compact"},
            signingKey
        ).final(jwksJsonString, "utf-8");
    } catch (error) {
        log.error("dsp.signedjwks.error", <string>error.message,
            logger.LogGroup.Technical, undefined
        );
        return "";
    }
}

/**
 * Get EntityStatement for SP
* @param {DspPrivateKeys} privateKeys DSP keys
* @param {string} host DSP hostname
* @param {LogSpan} logSpan optional Log instance
* @return {Promise<string} Signed EntityStatement for SP
 */
export async function getEntityStatement(
    privateKeys: DspPrivateKeys,
    host: string,
    logSpan?: logger.LogSpan
): Promise<string> {

    const log = logSpan || new logger.LogSpan();
    try {
        const now = Math.floor(Date.now() / 1000);
        const keyStore = jose.JWK.createKeyStore();
        await keyStore.add(privateKeys.entityKey, "pem", {use: "sig"});
        const entityStatement = {
            iss: `https://${host}`,
            sub: `https://${host}`,
            iat: now,
            exp: now + ENTITY_EXP_TIME,
            jwks: {
                keys: []
            },
            metadata: {
                openid_relying_party: {
                    redirect_uris: [`https://${host}/oauth/code`],
                    application_type: "web",
                    id_token_signed_response_alg: "RS256",
                    id_token_encrypted_response_alg: "RSA-OAEP",
                    id_token_encrypted_response_enc: "A128CBC-HS256",
                    request_object_signing_alg: "RS256",
                    token_endpoint_auth_method: "private_key_jwt",
                    token_endpoint_auth_signing_alg: "RS256",
                    client_registration_types: [],
                    organization_name: "Saippuakauppias",
                    signed_jwks_uri: `https://${host}/signed-jwks`
                }
            }
        };
        entityStatement.jwks = keyStore.toJSON(); // add the public part of the signing key(s)
        return await  jose.JWS.createSign(
            { fields: {
                alg: "RS256",
                typ: "entity-statement+jwt"
            }, format: "compact"},
            keyStore.get(entityStatement.jwks.keys[0].kid, { use: "sig" }) // get the first signing key and use it
        ).final(JSON.stringify(entityStatement), "utf-8");
    } catch (error) {
        log.error("dsp.entityStatement.error", <string>error.message,
            logger.LogGroup.Technical, undefined
        );
        return "";
    }
}

/**
 * Read ISB public signing key from the ISB Signed JWKS endpoint and store it to keyStore
 * @param {DspPrivateKeys} privateKeys DSP keys
 * @param {string} isbHost the hostname of ISB
 * @param {LogSpan} logSpan optional Log instance
 * @return {Promise<[string, number]>} signing key for ISB and expiry of ISB keys
 */
 export  async function getISBSigningKey(
    privateKeys: DspPrivateKeys,
    isbHost: string,
    logSpan?: logger.LogSpan
 ): Promise<readonly [string, number]> {
    const log = logSpan || new logger.LogSpan();

    let isbSignedJwksToken: JwksData;
    let keystore: jose.IKeyStore;
    const opts = {algorithms: SIGN_ALGS};
    // read ISB JWKS JWS from the ISB signed-JWKS
    try {
        isbSignedJwksToken = await httpGetJson(
            `https://${isbHost}/jwks/broker-signed`,
            false,
            {
                "Content-Type": "application/jose"
            }
        ) as JwksData;
        logger.debug("dsp.getISBSigningKey", "ISB JWKS JWS",
            logger.LogGroup.Technical,undefined, {isbSignedJwksToken});
        keystore = jose.JWK.createKeyStore();
        await keystore.add(privateKeys.isbEntitySigningKey, "pem", {use: "sig"});
    } catch (error) {
        logger.error("dsp.getISBSigningKey.fail", `reading ISB signed JWKS failed: ${<string>error.message}`,
            logger.LogGroup.Technical, undefined);
        throw error;
    }

    let verifiedIsbSigningKeys: JwksData;
    // Verify signing of the ISB JWKS
    try {
        const token = await jose.JWS.createVerify(keystore, opts).verify(isbSignedJwksToken);
        verifiedIsbSigningKeys = JSON.parse(token.payload as string);
    } catch (error) {
        logger.error("dsp.getISBSigningKey.fail", `verifing ISB signed JWKS failed: ${<string>error.message}`,
            logger.LogGroup.Technical, undefined);
        throw error;
    }

    // Verify ISS and SUB
    try {
        assert(verifiedIsbSigningKeys.iss === verifiedIsbSigningKeys.sub, new Error("ISS and SUB does not match"));
        assert(verifiedIsbSigningKeys.iss === `https://${isbHost}`, new Error("ISS does not match ISB host"));
    } catch (error) {
        logger.error("dsp.getISBSigningKey.fail", `verifing ISS or SUB failed: ${<string>error.message}`,
            logger.LogGroup.Technical, undefined);
        throw error;
    }

    return await jose.JWK.asKeyStore({keys: verifiedIsbSigningKeys.keys})
    .then((keyStore: jose.IKeyStore) => {
        return [keyStore, verifiedIsbSigningKeys.exp];
    })
    .catch((error: Error) => {
        logger.error("dsp.getISBSigningKey.fail", `storing ISB signing key to keystore failed: ${error.message}`,
            logger.LogGroup.Technical, undefined);
            throw error;
    });
}
