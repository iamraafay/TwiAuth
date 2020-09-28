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

protocol DictionaryRepresentable: Encodable {
    var dictionary: [String: Any] { get }
}

extension DictionaryRepresentable {
    var dictionary: [String: Any] {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase

        return (try? JSONSerialization.jsonObject(with: encoder.encode(self))) as? [String: Any] ?? [:]
    }
}

protocol OAuthAuthorizationHeader: DictionaryRepresentable {
    var oauthConsumerKey: String { get }
    var oauthNonce: String { get }
    var oauthSignatureMethod: String { get }
    var oauthTimestamp: String { get }
    var oauthVersion: String { get }
}

extension OAuthAuthorizationHeader {
    var oauthNonce: String {
        UUID().uuidString
    }

    var oauthSignatureMethod: String {
        "HMAC-SHA1"
    }

    var oauthTimestamp: String {
        String(Int(NSDate().timeIntervalSince1970))
    }

    var oauthVersion: String {
        "1.0"
    }
}

protocol SignedHeader: DictionaryRepresentable {
    var oauthSignature: String { get }
}

struct RequestTokenHeader: OAuthAuthorizationHeader {
    let oauthCallback: String
    let oauthConsumerKey: String
    let oauthNonce: String = UUID().uuidString
    let oauthSignatureMethod: String = "HMAC-SHA1"
    let oauthTimestamp: String = String(Int(NSDate().timeIntervalSince1970))
    let oauthVersion: String = "1.0"
}

struct SignedRequestTokenHeader: SignedHeader, OAuthAuthorizationHeader {
    let oauthSignature: String
    let oauthCallback: String
    let oauthConsumerKey: String
    let oauthNonce: String
    let oauthSignatureMethod: String
    let oauthTimestamp: String
    let oauthVersion: String
}

extension SignedRequestTokenHeader {
    init(requestToken header: RequestTokenHeader, oauthSignature: String) {
        self.oauthSignature = oauthSignature
        oauthCallback = header.oauthCallback
        oauthConsumerKey = header.oauthConsumerKey
        oauthNonce = header.oauthNonce
        oauthSignatureMethod = header.oauthSignatureMethod
        oauthTimestamp = header.oauthTimestamp
        oauthVersion = header.oauthVersion
    }
}

struct AccessTokenHeader: OAuthAuthorizationHeader {
    let oauthSignature: String
    let oauthConsumerKey: String
    let oauthToken: String
    let oauthVerifier: String
}

struct OAuthHeaderBuilder {
    func requestTokenHeader(with consumerKey: String, _ consumerSecret: String, and callback: String) -> String {
        let header = RequestTokenHeader(oauthCallback: callback, oauthConsumerKey: consumerKey)
        let signature = composeSignature(url: TwitterURL.requestToken.url.absoluteString, params: header.dictionary, consumerSecret: consumerSecret)
        let signedHeader = SignedRequestTokenHeader(requestToken: header, oauthSignature: signature)

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
