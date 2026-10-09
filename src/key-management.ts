// SPDX-FileCopyrightText: Copyright 2026 OP Pohjola (https://op.fi)
//
// SPDX-License-Identifier: MIT

import assert from "assert";
import { createPublicKey } from "node:crypto";
import {
    calculateJwkThumbprint, CompactSign, compactVerify, createLocalJWKSet,
    exportJWK, importPKCS8, importSPKI, JWK
} from "jose";
import * as logger from "5w-logger";

import {DspPrivateKeys, httpGetJson, toPkcs8Pem} from "./utils";

interface JwksData {
    readonly keys: ReadonlyArray<JWK>;
    readonly iss: string;
    readonly sub: string;
    readonly iat: number;
    readonly exp: number;
}

interface JwksKeys {
    readonly keys: ReadonlyArray<JWK>;
}

const ENTITY_EXP_TIME = 10 * 365 * 24 * 60 * 60; // 3650 days ~ 10 years
const JWKS_EXP_TIME = 90000; // 25 hours
export const SIGN_ALGS = ["RS256"];

export async function getKeyId(privateKeyPem: string): Promise<string> {
    const publicKey = await exportJWK(createPublicKey(privateKeyPem));
    return calculateJwkThumbprint(publicKey);
}

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
    try {
        const signingKey = await exportJWK(createPublicKey(privateKeys.signingKey));
        const encryptionKey = await exportJWK(createPublicKey(privateKeys.encyptionKey));
        signingKey.use = "sig";
        encryptionKey.use = "enc";
        signingKey.kid = await calculateJwkThumbprint(signingKey);
        encryptionKey.kid = await calculateJwkThumbprint(encryptionKey);
        return { keys: [signingKey, encryptionKey] };
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
        const signingKey = await importPKCS8(toPkcs8Pem(privateKeys.entityKey), "RS256");
        const kid = await getKeyId(privateKeys.entityKey);
        return new CompactSign(Buffer.from(jwksJsonString))
            .setProtectedHeader({ alg: "RS256", kid })
            .sign(signingKey);
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
        const entityKey = await importPKCS8(toPkcs8Pem(privateKeys.entityKey), "RS256");
        const entityJwk = await exportJWK(createPublicKey(privateKeys.entityKey));
        entityJwk.use = "sig";
        entityJwk.kid = await calculateJwkThumbprint(entityJwk);
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
        entityStatement.jwks = { keys: [entityJwk] };
        return new CompactSign(Buffer.from(JSON.stringify(entityStatement)))
            .setProtectedHeader({
                alg: "RS256",
                kid: entityJwk.kid,
                typ: "entity-statement+jwt"
            })
            .sign(entityKey);
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
 ): Promise<readonly [ReturnType<typeof createLocalJWKSet>, number]> {
    const log = logSpan || new logger.LogSpan();

    let isbSignedJwksToken: string;
    let verificationKey: Awaited<ReturnType<typeof importSPKI>>;
    // read ISB JWKS JWS from the ISB signed-JWKS
    try {
        isbSignedJwksToken = await httpGetJson(
            `https://${isbHost}/jwks/broker-signed`,
            false,
            {
                "Content-Type": "application/jwk-set+jwt"
            }
        ) as string;
        logger.debug("dsp.getISBSigningKey", "ISB JWKS JWS",
            logger.LogGroup.Technical,undefined, {isbSignedJwksToken});
        verificationKey = await importSPKI(privateKeys.isbEntitySigningKey, "RS256");
    } catch (error) {
        logger.error("dsp.getISBSigningKey.fail", `reading ISB signed JWKS failed: ${<string>error.message}`,
            logger.LogGroup.Technical, undefined);
        throw error;
    }

    let verifiedIsbSigningKeys: JwksData;
    // Verify signing of the ISB JWKS
    try {
        const token = await compactVerify(isbSignedJwksToken, verificationKey, {
            algorithms: SIGN_ALGS
        });
        verifiedIsbSigningKeys = JSON.parse(Buffer.from(token.payload).toString());
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

    try {
        const keySet = createLocalJWKSet({ keys: [...verifiedIsbSigningKeys.keys] });
        return [keySet, verifiedIsbSigningKeys.exp];
    } catch (error) {
        logger.error("dsp.getISBSigningKey.fail", `storing ISB signing key to keystore failed: ${error.message}`,
            logger.LogGroup.Technical, undefined);
        throw error;
    }
}
