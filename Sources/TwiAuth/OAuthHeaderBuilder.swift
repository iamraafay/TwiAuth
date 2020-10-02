//
//  OAuthHeaderBuilder.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2020-09-27.
//

import Foundation
import CommonCrypto

enum TwiHTTPMethod: String, Equatable {
    case get = "GET", post = "POST"
}

struct OAuthHeaderBuilder {
    func requestTokenHeader(with consumerKey: String, _ consumerSecret: String, and callback: String) -> String {
        let header = RequestTokenHeader(oauthCallback: callback, oauthConsumerKey: consumerKey)
        let signature = composeSignature(url: TwitterURL.requestToken.url.absoluteString, params: header.dictionary, consumerSecret: consumerSecret)
        let signedHeader = SignedRequestTokenHeader(requestToken: header, oauthSignature: signature)

        return authorizationHeader(params: signedHeader.dictionary)
    }

    func accessTokenVerifierHeader(with consumerKey: String, oauthToken: String, oauthVerifier: String, _ consumerSecret: String, and callback: String) -> String {
        let header = AccessTokenVerifierHeader(oauthConsumerKey: consumerKey, oauthToken: oauthToken, oauthVerifier: oauthVerifier)
        let signature = composeSignature(url: TwitterURL.accessToken.url.absoluteString, params: header.dictionary, consumerSecret: consumerSecret)
        let signedHeader = SignedAccessTokenVerifierHeader(requestToken: header, oauthSignature: signature)

        return authorizationHeader(params: signedHeader.dictionary)
    }

    func accessTokenHeader(url: String, method: TwiHTTPMethod, consumerKey: String, consumerSecret: String, oauthToken: String, oauthSecret: String) -> String {
        let header = AccessTokenHeader(oauthConsumerKey: consumerKey, oauthToken: oauthToken)
        let signature = composeSignature(httpMethod: method, url: url, params: header.dictionary, consumerSecret: consumerSecret, oAuthTokenSecret: oauthSecret)
        let signedHeader = SignedAccessTokenHeader(requestToken: header, oauthSignature: signature)

        return authorizationHeader(params: signedHeader.dictionary)
    }
    
    func composeSignature(httpMethod: TwiHTTPMethod = .post,
                   url: String,
                   params: [String: Any],
                   consumerSecret: String,
                   oAuthTokenSecret: String? = nil) -> String {

        let signingKey = signatureKey(consumerSecret, oAuthTokenSecret)
        let signatureBase = signatureBaseString(httpMethod, url, params)

        return HMAC_SHA1(signingKey: signingKey, signatureBase: signatureBase)
    }

    func authorizationHeader(params: [String: Any]) -> String {
        var parts: [String] = []
        for param in params {
            let key = param.key.urlEncoded
            let val = "\(param.value)".urlEncoded
            parts.append("\(key)=\"\(val)\"")
        }

        return "OAuth " + parts.sorted().joined(separator: ", ")
    }

    private func signatureKey(_ consumerSecret: String, _ oAuthTokenSecret: String?) -> String {
        guard let oAuthSecret = oAuthTokenSecret?.urlEncoded else {
            return consumerSecret.urlEncoded+"&"
        }

        return consumerSecret.urlEncoded+"&"+oAuthSecret
    }

    private func signatureParameterString(params: [String: Any]) -> String {
        var result: [String] = []
        for param in params {
            let key = param.key.urlEncoded
            let val = "\(param.value)".urlEncoded
            result.append("\(key)=\(val)")
        }

        return result.sorted().joined(separator: "&")
    }

    private func signatureBaseString(_ httpMethod: TwiHTTPMethod, _ url: String, _ params: [String: Any]) -> String {
        let parameterString = signatureParameterString(params: params)
        return httpMethod.rawValue + "&" + url.urlEncoded + "&" + parameterString.urlEncoded
    }

    private func HMAC_SHA1(signingKey: String, signatureBase: String) -> String {
        // HMAC-SHA1 hashing algorithm returned as a base64 encoded string
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), signingKey, signingKey.count, signatureBase, signatureBase.count, &digest)
        let data = Data(digest)

        return data.base64EncodedString()
    }
}

extension String {
    var urlEncoded: String {
        var charset: CharacterSet = .urlQueryAllowed
        charset.remove(charactersIn: "\n:#/?@!$&'()*+,;=")
        return self.addingPercentEncoding(withAllowedCharacters: charset)!
    }
}


extension String {
    var urlQueryStringParameters: [String: String] {
        // breaks apart query string into a dictionary of values
        var params = [String: String]()
        let items = self.split(separator: "&")
        for item in items {
            let combo = item.split(separator: "=")
            if combo.count == 2 {
                let key = "\(combo[0])"
                let val = "\(combo[1])"
                params[key] = val
            }
        }
        return params
    }
}
