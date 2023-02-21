import * as logger from "checkout-logger";
import Crypto from "crypto-random-string";
import * as Hapi from "@hapi/hapi";
import i18next from "i18next";
import i18nBackend from "i18next-fs-backend";
import * as jose from "node-jose";
import * as uuid from "uuid";
import * as Vision from "@hapi/vision";
import * as Inert from "@hapi/inert";
import {
    getDSPKeys, httpGetJson, EmbeddedUIData, embeddedInfoSchema,
    HttpPostUrlEncodedData, httpPostFormUrlEncoded, translate, DspPrivateKeys
} from "./utils";
import { getEntityStatement, getISBSigningKey, getSignedJwks } from "./key-management";

interface TokenResponse {
    readonly id_token: string;
    readonly [key:string]: any;
}

interface Spname {
    readonly fi:string;
    readonly sv:string;
    readonly en:string;
}

const internals: any = {};


internals.start = async function () {

    const server = new Hapi.Server({ port: 80 });

    // Register Hapi plugins
    try {
        await server.register({
            plugin: require("@hapi/yar"),
            options: {
                storeBlank: false,
                cookieOptions: {
                    password: "the-password-must-be-at-least-32-characters-long",
                    isSecure: false // this shall be set as true in production as https is mandatory
                }
            }
        });
      } catch (err) {
          logger.error("dsp.register.yar", `registration failed: ${<string>err.message}`,
            logger.LogGroup.Technical, undefined);
      }

    try {
        await server.register(Vision);
    }
    catch (err) {
        logger.error("dsp.register.vision", `registration failed: ${<string>err.message}`,
        logger.LogGroup.Technical, undefined);
    }

    try {
        await server.register(Inert);
    }
    catch (err) {
        logger.error("dsp.register.inert", `registration failed: ${<string>err.message}`,
            logger.LogGroup.Technical, undefined);
    }

    const isbHost = process.env["ISB_HOST"] || undefined;
    const clientId = process.env["CLIENT_ID"] || undefined;
    const spnameJson: Spname = JSON.parse(process.env["SPNAME"]) || {en: "Soap for the people"};

    let privateKeys: DspPrivateKeys ;
    try {
        privateKeys = await getDSPKeys();
    } catch (error) {
        logger.error("dsp.keys.error", `fetching keys failed ${<string>error.message}`,
              logger.LogGroup.Technical, undefined);
        privateKeys = {
            encyptionKey: " ",
            signingKey: " ",
            entityKey: " ",
            isbEntitySigningKey: " "
        };
    }


    // the refresh time for the isbSigningKey
    let isbSigningKeyRefreshTime: number = 0;
    // The JWKS key store for the ISB signing key
    let isbKeyStore: jose.JWK.KeyStore;

    /**
     * date and time formatting options
     */
    const options: Intl.DateTimeFormatOptions = {
        day: "numeric",
        month: "long",
        hour: "numeric",
        minute: "numeric",
        timeZone: "Europe/Helsinki",
    };

    /**
     * converts unixTime returned from ISB to human readable time
     *
     * @param {number} unixTime - time of authentication in unix milliseconds
     * @return {string}
     */
    function getFormattedTime(unixTime: number): string {
        return new Date(unixTime * 1000).toLocaleString("en-US", options);
    }

    /**
     * make clientAssertion JWS
     *
     * @return {Promise<string>}
     */
    async function makeClientAssertion(): Promise<string> {
        const payload = {
            iss: clientId,
            sub: clientId,
            aud: `https://${isbHost}/oauth/token`,
            jti: uuid.v4().toString(),
            exp: Math.floor(Date.now() / 1000) + 10 * 60
        };
        const payloadJSON = JSON.stringify(payload);
        const signingKey = await jose.JWK.asKey(privateKeys.signingKey, "pem");
        return <string>jose.JWS.createSign({ format: "compact" }, signingKey).final(payloadJSON, "utf-8");
    }

    /**
     * make JWS for /oauth/authorize
     *
     * @param {Hapi.Request} request - Hapi http-request
     * @param {string} state - state used in authentication
     * @param {string} nonce - nonce used in authentication
     * @return {Promise<string>}
     */
    async function makeauthToken(request: Hapi.Request, state: string, nonce: string): Promise<string> {
        const payload = {
            iss: clientId,
            aud: `https://${isbHost}/oauth/authorize`,
            ui_locales: "fi",
            client_id: clientId,
            response_type: "code",
            // note that https should be used for redirect_uri in production
            redirect_uri: `http://${request.info.host}/oauth/code`,
            state: state,
            nonce: nonce,
            scope: "openid profile personal_identity_code"
        };

        // set the default ftn_spname
        payload["ftn_spname"] = spnameJson.en;

        if (request.yar.get("lang")) {
            payload["ui_locales"] = request.yar.get("lang"); // set language
            // set also localised ftn_spname
            payload["ftn_spname"] = spnameJson[request.yar.get("lang")] || spnameJson.en;
        }

        if (request.query.promptBox) {
            payload["prompt"] = "consent";
        }

        if (request.query.idButton) {
            payload["ftn_idp_id"] = request.query.idButton;
        }
        if (request.query.purpose) {
            if (request.query.purpose === "weak") {
                payload.scope += " weak";
            }
            else if (request.query.purpose === "strong") {
                payload.scope += " strong";
            }
        }
        const payloadJSON = JSON.stringify(payload);
        const signingKey = await jose.JWK.asKey(privateKeys.signingKey, "pem");
        return <string>jose.JWS.createSign({ format: "compact" }, signingKey).final(payloadJSON, "utf-8");
    }

    /**
     * Try decrypting and verifying the token with the key we have.
     *
     * @param {string} token encypted and signed JSON web token (ID Token)
     * @return {Promise<string>} decrypted and succesfully verified ID Token or error
     */
    async function decryptToken(token: string): Promise<string> {
        try {
            const privKey = await jose.JWK.asKey(privateKeys.encyptionKey, "pem");
            logger.info("dsp.decrypting", "Decrypting with key", logger.LogGroup.Technical, undefined,
                {kid: privKey.kid});
            const decrypted = (await jose.JWE.createDecrypt(privKey)
                        .decrypt(token)
                        ).plaintext.toString();
            logger.info("dsp.decrypting.ok", "Decrypt succeeded with key",
                logger.LogGroup.Technical, undefined, {decrypted});
            try {
                if (Date.now() > isbSigningKeyRefreshTime) {
                    // Refresh ISB signing key
                    let exp: number;
                    [isbKeyStore, exp] = await getISBSigningKey(privateKeys,isbHost);
                    // set refresh time according to ISB JWKS exp
                    isbSigningKeyRefreshTime = exp * 1000;
                }
                const verificationResult = await jose.JWS.createVerify(isbKeyStore).verify(decrypted);
                return verificationResult.payload.toString();
            } catch (err) {
                logger.error("dsp.verifying.fail", `Verification failed: ${<string>err.message}`,
                    logger.LogGroup.Technical, undefined);
                return "{\"err\":\"Could not verify token\"}";
            }
        } catch (err) {
            logger.info("dsp.decrypting.keyfail", `decrypt failed: ${<string>err.message}`,
                logger.LogGroup.Technical, undefined,
                {error: err, token, key: privateKeys.encyptionKey});
        }
    }

    // init Handlebars
    const manager = server.views({
        engines: { hbs: require("handlebars") },
        path: "templates",
        partialsPath: "templates/partials",
        relativeTo: __dirname
    });

    i18next.use(i18nBackend).init({
        preload: ["en", "fi", "sv"],
        fallbackLng: "en",
        backend: {
            loadPath: __dirname + "/locales/{{lng}}/{{ns}}.json"
        }
    // eslint-disable-next-line functional/no-return-void
    }).catch((error) => {
        logger.error("dsp.i18next.init.fail", `I18next init failed: ${<string>error.message}`,
                    logger.LogGroup.Technical, undefined);
    });

    // i18next translate helper
    manager.registerHelper("t", translate);

    // Routes
    server.route({
        method: "GET",
        path: "/oauth/authorize",
        handler: async (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
            // Create oauth/authorize request for OP ISB
            const state = Crypto({length: 22});
            const nonce = Crypto({length: 22});
            request.yar.set("state", state);
            request.yar.set("nonce", nonce);
            try {
                const token = await makeauthToken(request, state, nonce);
                // Redirect to the OP ISB /oauth/authorize
                try {
                    const authUrl = `https://${isbHost}/oauth/authorize?request=${token}`;
                    return h.redirect(authUrl);
                }
                catch (err) {
                    logger.error("dsp.oauth.authorize", <string>err.message,
                        logger.LogGroup.Technical, undefined);
                    request.yar.set("error", err.message);
                    return h.view("template", { error: err.message });
                }
            }
            catch (err) {
                logger.error("dsp.auth.fail", `making JSW token for auth failed: ${<string>err.message}`,
                    logger.LogGroup.Technical, undefined);
                request.yar.set("error", err.message);
                return h.view("template", { error: err.message });
            }
        }
    });

    server.route({
        method: "GET",
        path: "/oauth/code",
        handler: (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
            let redirectUrl: string;
            if (request.yar.get("mode") === "normal") {
                redirectUrl = "/";
            }
            else {
                redirectUrl = "/embedded";
            }
            // Check that session matches
            if (request.query.state && request.query.state !== request.yar.get("state")) {
                logger.error("dsp.auth.fail", "state does not match",
                            logger.LogGroup.Technical, undefined, {
                                origState: request.yar.get("state"),
                                state: request.query.state
                            }
                );
                request.yar.set("error", "state does match");
                return h
                        .response("redirecting")
                        .redirect(redirectUrl);
            }
            // check if authentication failed
            if (request.query && request.query.error)  {
                logger.error("dsp.auth.fail", "ISB returned error",
                            logger.LogGroup.Technical, undefined, {error: request.query.error});
                // store error and errorDescription if not cancel
                if (request.query.error !== "cancel") {
                    request.yar.set("error", request.query.error);
                    if (request.query.error_description) {
                        request.yar.set("errorDescription", request.query.error_description);
                    }
                }
                return h
                        .response("redirecting")
                        .redirect(redirectUrl);
            }
            return makeClientAssertion()
                .then( (clientAssertion) => {
                    // Create data for ID Token request
                    const data: HttpPostUrlEncodedData = {
                        client_id: clientId,
                        grant_type: "authorization_code",
                        code: request.query.code as string,
                        // note that https should be used for redirect_uri in production
                        redirect_uri: `http://${request.info.host}/oauth/code`,
                        client_assertion_type:
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        client_assertion: clientAssertion
                    };
                    // Request ID Token
                    return  httpPostFormUrlEncoded(
                        `https://${isbHost}/oauth/token`,
                        {"Content-Type": "application/x-www-form-urlencoded"},
                        data)
                        .then((tokenResponse: TokenResponse) => {
                            logger.debug(
                                "dsp.tokenresponse", "Token response",
                                logger.LogGroup.Technical, undefined,
                                {
                                    response: tokenResponse,
                                }
                            );
                            return decryptToken(tokenResponse.id_token)
                                .then((result) => {
                                    const credentials = JSON.parse(result);
                                    logger.info(
                                        "dsp.tokenresponse.token", "token verification ok",
                                        logger.LogGroup.Technical, undefined, {results: result}
                                    );
                                    // check that nonce matches
                                    if (credentials && credentials.nonce !== request.yar.get("nonce")) {
                                        logger.error(
                                            "dsp.tokenresponse.nonce", "nonce does not match",
                                            logger.LogGroup.Technical, undefined
                                        );
                                        return "{\"err\":\"nonce does not match\"}";
                                    }
                                    request.yar.set("profile", credentials);
                                    return h
                                        .response("redirecting")
                                        .redirect(redirectUrl);
                                })
                                .catch((err) => {
                                    logger.error("dsp.tokenresponse.fail",
                                        `decrypt token failed: ${<string>err.message}`,
                                        logger.LogGroup.Technical, undefined);
                                    request.yar.set("error", err.message);
                                    return h
                                        .response("redirecting")
                                        .redirect(redirectUrl);
                                });
                        })
                        .catch((err) => {
                            logger.error("dsp.tokenresponse.fail",
                                `error in ISB oauth/token communication: ${<string>err.message}`,
                                logger.LogGroup.Technical, undefined);
                            request.yar.set("error", err.message);
                            return h
                                .response("redirecting")
                                .redirect(redirectUrl);
                        });
                })
                .catch((err) => {
                    logger.error("dsp.auth.fail", `making JSW token for auth failed: ${<string>err.message}`,
                            logger.LogGroup.Technical, undefined);
                    request.yar.set("error", err.message);
                    return h.view(
                        "template",
                        {error: err.message}
                    );
                });
        }
    });

    server.route({
        method: "GET",
        path: "/logout",
        handler: (request, h) => {
            request.yar.clear("profile");
            request.yar.clear("error");
            request.yar.clear("errorDescription");
            request.yar.clear("lang");
            request.yar.clear("state");
            request.yar.clear("nonce");
            let redirectUrl: string;
            if (request.yar.get("mode") === "normal") {
                redirectUrl = "/";
            }
            else {
                redirectUrl = "/embedded";
            }
            return h
                .response("redirecting")
                .redirect(redirectUrl);
        }
    });

    server.route({
        method: "GET",
        path: "/",
        handler: (request, h) => {
            const profile = request.yar.get("profile");
            const error = request.yar.get("error");
            const errorDescription = request.yar.get("errorDescription");
            request.yar.clear("error");
            request.yar.clear("errorDescription");
            request.yar.clear("lang");
            request.yar.clear("state");
            request.yar.clear("nonce");
            request.yar.set("mode", "normal");
            const rawProfile = JSON.stringify(profile, null, 2) || null;
            const authTime: string | null = profile && profile.auth_time ?
                getFormattedTime(<number>profile.auth_time) : null;

            const hosted = true;
            const landing = !profile && !error;

            const lang = request.query.lang ? <string>request.query.lang : "en";
            request.yar.set("lang", lang);

            const returnUrl = "/";
            return h.view(
                "template",
                {hosted, landing, profile, rawProfile, error, errorDescription, authTime, returnUrl}
            );
        }
    });

    server.route({
        method: "GET",
        path: "/embedded",
        handler: async (request, h) => {
            const profile = request.yar.get("profile");
            let error = request.yar.get("error");
            let errorDescription = request.yar.get("errorDescription");
            request.yar.clear("error");
            request.yar.clear("errorDescription");
            request.yar.set("mode", "embedded");
            request.yar.clear("state");
            request.yar.clear("nonce");
            const rawProfile = JSON.stringify(profile, null, 2) || null;
            const authTime: string | null = profile && profile.auth_time ?
                getFormattedTime(<number>profile.auth_time) : null;

            const lang = request.query.lang ? <string>request.query.lang : "en";
            request.yar.set("lang", lang);
            let embeddedInfo: EmbeddedUIData;
            if (error === null && profile === null ) {
                const embeddedUri = `https://${isbHost}/api/embedded-ui/${clientId}?lang=${lang}`;
                try {
                    const embeddedDataString: string = await httpGetJson(
                        embeddedUri,
                        false,
                        {
                            "Content-Type": "application/json"
                        }
                    ) as string;
                    embeddedInfo = JSON.parse(embeddedDataString
                        .replace(/<(?:.|\n)*?>/gm, "") // Remove html tags
                        // replace \r and \n with <br><br> to handle multi-line disturbance notifications
                        .replace(/(?:\\[rn])+/g, "<br><br>")
                    );
                    const validationResult = embeddedInfoSchema.validate(embeddedInfo);
                    if (validationResult.error) {
                        throw(validationResult.error);
                    }
                }
                catch (err) {
                    error = "Embedded identification wall could not be formed";
                    errorDescription = err;
                }
            }

            const embedded = true;
            const landing = !profile && !error;

            const returnUrl = "/embedded";

            return h.view("template", {embedded, landing, profile, rawProfile, error, errorDescription,
                                                authTime, embeddedInfo, returnUrl});
        }
    });

    server.route({
        method: "GET",
        path: "/signed-jwks",
        handler: async (request, h) => {
            return h.response(await getSignedJwks(privateKeys, request.info.host)).type("application/jwk-set+jwt");
        }
    });

    server.route({
        method: "GET",
        path: "/.well-known/openid-federation",
        handler: async (request, h) => {
            return h.response(await getEntityStatement(privateKeys,request.info.host))
            .type("application/entity-statement+jwt");
        }
    });


    server.route({
        method: "GET",
        path: "/css/{param*}",
        handler: {
          directory: {
            path: "dist/public"
          }
        }
      });

    server.route({
        method: "GET",
        path: "/robots.txt",
        handler: (_req, h) => {
            return h
                .response("User-agent: *\nDisallow: /\n")
                .type("text/plain");
        }
    });

    try {
        await server.start();
    }
    catch (err) {
        logger.error("dsp.server.fail", `server did not start: ${<string>err.message}`,
            logger.LogGroup.Technical, undefined);
    }
};

internals.start();
