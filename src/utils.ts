import * as fs from "fs";
import * as http from "http";
import * as https from "https";
import i18next from "i18next";
import * as Joi from "joi";

import * as logger from "checkout-logger";

export interface IdentityProvider {
    readonly name: string;
    readonly imageUrl: string;
    readonly ftn_idp_id: string;
}

export interface DisturbanceInfo {
    readonly header: string;
    readonly text: string;
}

export interface EmbeddedUIData {
    readonly identityProviders: ReadonlyArray<IdentityProvider>;
    readonly isbProviderInfo: string;
    readonly isbConsent: string;
    readonly disturbanceInfo?: DisturbanceInfo;
}

export interface DspPrivateKeys {
    readonly signingKey: string;
    readonly encyptionKey: string;
    readonly entityKey: string;
    readonly isbEntitySigningKey: string;
}

export const embeddedInfoSchema = Joi.object().keys({
    identityProviders: Joi.array().items(
        Joi.object().keys({
            name: Joi.string().required(),
            imageUrl: Joi.string().required(),
            ftn_idp_id: Joi.string().required()
        })
    ),
    isbProviderInfo: Joi.string().required(),
    isbConsent: Joi.string().required(),
    privacyNoticeText: Joi.string().required(),
    privacyNoticeLink: Joi.string().required(),
    disturbanceInfo: Joi.object().keys({header: Joi.string(), text: Joi.string()})
});

export interface HttpPostUrlEncodedData {
    readonly [key: string]: string;
}

/**
* HTTP(s) GET JSON helper
*
* @param {string} endpointUrl The endpoint URL for getting the JSON data from
* @param {boolean} parseResult indicates whether to parse the JSON data or not. Default is true.
* @param {readonly [key: string]: string } headers headers for the request
* @return {Promise<object | string>} returned data
*/
export async function httpGetJson(
    endpointUrl: string,
    parseResult: boolean = true,
    headers: { readonly [key: string]: string }): Promise<object | string> {

    // eslint-disable-next-line functional/no-return-void
    return new Promise<any>((accept, reject) => {
        const parsedUrl: URL = new URL(endpointUrl);
        const queryParams: string = parsedUrl.searchParams.toString() ?
            `?${parsedUrl.searchParams.toString()}` : "";
        const options: http.RequestOptions = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port ? Number(parsedUrl.port) : 443,
            path: parsedUrl.pathname + queryParams,
            method: "GET",
            timeout: 5000,  // 5 seconds
            headers: {
                ...headers
            }
        };

        let req: http.ClientRequest;
        // eslint-disable-next-line functional/no-return-void
        const callback = (response: http.IncomingMessage) => {
            let result = "";
            // eslint-disable-next-line functional/no-return-void
            response.on("data", (chunk: Buffer) => {
                // eslint-disable-next-line @typescript-eslint/restrict-plus-operands
                result += chunk;
            });
            // eslint-disable-next-line functional/no-return-void
            response.on("end", () => {
                if (response.statusCode === 404) {
                    logger.debug("dsp.http-get.response.not-found",
                        "Outbound GET: not found", logger.LogGroup.Session);
                    reject(new Error(response.statusMessage));
                } else if (response.statusCode >= 300) {
                    logger.error("dsp.http-get.response.errorstatus",
                              `Outbound GET: ${response.statusMessage}`, logger.LogGroup.Session, undefined,
                              { status_code: response.statusCode });
                    reject(new Error(response.statusMessage));
                } else {
                    let finalResult: Object;
                    try {
                        if (parseResult) {
                            finalResult = JSON.parse(result);
                        } else {
                            finalResult = result;
                        }
                    }
                    catch (error) {
                        logger.error("dsp.http-get.response.faulty", <string>error.toString(),
                            logger.LogGroup.Technical, undefined, {result, endpointUrl });
                        return reject(error);
                    }
                    accept(finalResult);
                }
            });
            // eslint-disable-next-line functional/no-return-void
            response.on("error", (error: Error) => {
                logger.error("dsp.http-get.response.error", error.toString(), logger.LogGroup.Technical,
                          undefined, {endpointUrl});
                return reject(error);
            });
        };

        try {
            if (parsedUrl.protocol === "https:") {
                req = https.request(options, callback);
            } else if (parsedUrl.protocol === "http:") {
                req = http.request(options, callback);
            } else {
                throw new Error("Unsupported api endpoint protocol");
            }
            // eslint-disable-next-line functional/no-return-void
            req.on("error", function(error: Error) {
                logger.error("dsp.http-get.request.error", error.toString(), logger.LogGroup.Technical,
                          undefined, {endpointUrl});
                return reject(error);
            });
            // eslint-disable-next-line functional/no-return-void
            req.on("timeout", () => {
                 req.destroy();
             });
            req.end();
        } catch (err) {
            logger.error("dsp.http-get.response.error", <string>err.toString(), logger.LogGroup.Technical,
                          undefined, {endpointUrl});
            return reject(err);
        }
    });
}

/**
* HTTP(s) POST FormUrlEncoded helper
*
* @param {string} endpointUrl The endpoint URL for posting the payload to
* @param {readonly [key: string]: string} headers Additional request headers
* @param {HttpPostUrlEncodedData} payload HttpPostUrlEncodedData to post
* @param {LogSpan} logSpan optional Log instance
* @return {Promise<any>} response
*/
export async function httpPostFormUrlEncoded(
   endpointUrl: string,
   headers: { readonly [key: string]: string },
   payload: HttpPostUrlEncodedData,
   logSpan?: logger.LogSpan,
): Promise<any> {

   const log = logSpan || new logger.LogSpan();
   const timeout = 5000; // 5 seconds

   let data: string = "";

   // Goes through the payload and formats the data as string in &key=data format
   // data is also URI encoded
   try {
       // eslint-disable-next-line functional/no-return-void
       Object.keys(payload).forEach(key => {
            data = (data ? data + "&" : "") + key + "=" + encodeURIComponent(payload[key]);
       });
   } catch (error) {
       log.warn("dsp.http-post.form.serialize", "Cannot serialize data",
           logger.LogGroup.Technical, undefined,
           {
               error: error.message,
               endpointUrl,
           }
       );
       throw error;
   }

   log.debug("dsp.http-post.form", "Outbound REST POST",
       logger.LogGroup.Technical, undefined,
           {
               endpointUrl
           }
       );
    // eslint-disable-next-line functional/no-return-void
    return new Promise<any>((accept, reject) => {
        const parsedUrl: URL = new URL(endpointUrl);

       const options: https.RequestOptions = {
           hostname: parsedUrl.hostname,
           port: parsedUrl.port ? Number(parsedUrl.port) : 443,
           path: parsedUrl.pathname,
           method: "POST",
           timeout: timeout,
           headers: {
               "Content-Length": Buffer.byteLength(data, "utf-8"),
               ...headers
           }
       };

       let req: http.ClientRequest;
       // eslint-disable-next-line functional/no-return-void
       const callback = (response: http.IncomingMessage) => {
           let result = "";
           // eslint-disable-next-line functional/no-return-void
           response.on("data", (chunk: Buffer) => {
               // eslint-disable-next-line @typescript-eslint/restrict-plus-operands
               result += chunk;
           });
           // eslint-disable-next-line functional/no-return-void
           response.on("end", () => {
               let finalResult: Object;
               try {
                   finalResult = JSON.parse(result);
               }
               catch (error) {
                   log.warn("dsp.http-post.form.response.faulty", <string>error.toString(),
                       logger.LogGroup.Technical, undefined,
                       {
                           payload,
                           result,
                           endpointUrl,
                           error: error.message
                       }
                   );
                   return reject(error);
               }
               accept(finalResult);
           });
           // eslint-disable-next-line functional/no-return-void
           response.on("error", (error: Error) => {
               log.warn("dsp.http-post.form.response.error", error.toString(),
                   logger.LogGroup.Technical, undefined,
                   {
                       payload,
                       endpointUrl,
                       error: error.message
                   }
               );
               return reject(error);
           });
       };

       try {
           if (parsedUrl.protocol === "https:") {
               req = https.request(options, callback);
           } else if (parsedUrl.protocol === "http:") {
               req = http.request(options, callback);
           } else {
               throw new Error("Unsupported api endpoint protocol");
           }
           req.write(data);
           // eslint-disable-next-line functional/no-return-void
           req.on("error", function (error: Error) {
               log.warn("dsp.http-post.form.request.error", error.toString(),
                   logger.LogGroup.Technical, undefined,
                   {
                       endpointUrl,
                       error: error.message
                   }
               );
               return reject(error);
           });
           // eslint-disable-next-line functional/no-return-void
           req.on("timeout", () => {
               req.destroy();
           });
           req.end();
       } catch (err) {
           return reject(err);
       }
   });
}

/**
* i18next translate function
*
* @param {LogSpan} text text to be translated
* @return {string} translated text
*/
export function translate(text: string): string {
    return i18next.t(text);
}

/**
* Loads DSP keys from file
*
* @param {LogSpan} logSpan optional Log instance
* @return {Promise<DspPrivateKeys>} the private keys for DSP
*/
export function getDSPKeys(logSpan?: logger.LogSpan): Promise<DspPrivateKeys> {

    const log = logSpan || new logger.LogSpan();
    log.info("dsp.utils.getDSPKeys", "Loading keys from file", logger.LogGroup.Technical);
    try {
        const privateKeys: DspPrivateKeys = {
            encyptionKey: fs.readFileSync("keys/sandbox-sp-key.pem").toString(),
            signingKey: fs.readFileSync("keys/sp-signing-key.pem").toString(),
            entityKey: fs.readFileSync("keys/sandbox-sp-entity-signing-key.pem").toString(),
            isbEntitySigningKey: fs.readFileSync("keys/sandbox-isb-entity-signing-pubkey.pem").toString(),
        };
        return Promise.resolve(privateKeys);
    } catch (error) {
        log.error("dsp.utils.getDSPKeys.file.error", <string>error.message, logger.LogGroup.Technical,
            undefined, {error: error.toString()});
        throw error;
    }
}

