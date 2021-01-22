//
//  SignatureComposer.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-22.
//

import Foundation
import CommonCrypto

enum SignatureComposer {
    static func compose(
        httpMethod: TwiHTTPMethod = .post,
        url: String,
        params: [String: Any],
        consumerSecret: String,
        oAuthTokenSecret: String?
    ) -> String {

        let signingKey = signatureKey(consumerSecret, oAuthTokenSecret)
        let signatureBase = signatureBaseString(httpMethod, url, params)

        return HMAC_SHA1(signingKey: signingKey, signatureBase: signatureBase)
    }

    private static func signatureKey(_ consumerSecret: String, _ oAuthTokenSecret: String?) -> String {
        guard let oAuthSecret = oAuthTokenSecret?.urlEncoded else {
            return consumerSecret.urlEncoded+"&"
        }

        return consumerSecret.urlEncoded+"&"+oAuthSecret
    }

    private static func signatureParameterString(params: [String: Any]) -> String {
        var result: [String] = []
        for param in params {
            let key = param.key.urlEncoded
            let val = "\(param.value)".urlEncoded
            result.append("\(key)=\(val)")
        }

        return result.sorted().joined(separator: "&")
    }

    private static func signatureBaseString(_ httpMethod: TwiHTTPMethod, _ url: String, _ params: [String: Any]) -> String {
        let parameterString = signatureParameterString(params: params)
        return httpMethod.rawValue + "&" + url.urlEncoded + "&" + parameterString.urlEncoded
    }

    private static func HMAC_SHA1(signingKey: String, signatureBase: String) -> String {
        // HMAC-SHA1 hashing algorithm returned as a base64 encoded string
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), signingKey, signingKey.count, signatureBase, signatureBase.count, &digest)
        let data = Data(digest)

        return data.base64EncodedString()
    }
}
