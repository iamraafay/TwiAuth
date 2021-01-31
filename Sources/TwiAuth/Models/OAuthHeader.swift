//
//  OAuthHeader.swift
//  TwiAuth
//
//  Copyright (c) 2020 Mohammad Abdurraafay

import Foundation

protocol OAuthHeader: DictionaryRepresentable {
    var oauthSignature: String? { get set }
    var oauthConsumerKey: String { get }
    var oauthNonce: String { get }
    var oauthSignatureMethod: String { get }
    var oauthTimestamp: String { get }
    var oauthVersion: String { get }

    var authorized: String { get }

    mutating func sign(for url: URL, method: TwiHTTPMethod, consumerSecret: String, oAuthTokenSecret: String?, parameters: [String: String])
}

struct RequestTokenHeader: OAuthHeader {
    var oauthSignature: String? = nil
    let oauthCallback: String
    let oauthConsumerKey: String
    let oauthNonce: String = UUID().uuidString
    let oauthSignatureMethod: String = "HMAC-SHA1"
    let oauthTimestamp: String = String(Int(NSDate().timeIntervalSince1970))
    let oauthVersion: String = "1.0"
}

struct AccessTokenVerifierHeader: OAuthHeader {
    var oauthSignature: String? = nil
    let oauthConsumerKey: String
    let oauthToken: String
    let oauthVerifier: String
    let oauthNonce: String = UUID().uuidString
    let oauthSignatureMethod: String = "HMAC-SHA1"
    let oauthTimestamp: String = String(Int(NSDate().timeIntervalSince1970))
    let oauthVersion: String = "1.0"
}

/** POST
 --header 'authorization: OAuth
 oauth_consumer_key="oauth_customer_key",
 oauth_nonce="generated_oauth_nonce",
 oauth_signature="generated_oauth_signature",
 oauth_signature_method="HMAC-SHA1",
 oauth_timestamp="generated_timestamp",
 oauth_token="oauth_token",
 oauth_version="1.0"'
 */
struct AccessTokenHeader: OAuthHeader {
    var oauthSignature: String? = nil
    let oauthConsumerKey: String
    let oauthToken: String
    let oauthNonce: String = UUID().uuidString
    let oauthSignatureMethod: String = "HMAC-SHA1"
    let oauthTimestamp: String = String(Int(NSDate().timeIntervalSince1970))
    let oauthVersion: String = "1.0"
}

extension OAuthHeader {
    var authorized: String {
        guard oauthSignature != nil else {
            fatalError("Needed signature for header to be authorized")
        }
        let params = dictionary
        var parts: [String] = []
        for param in params {
            let key = param.key.urlEncoded
            let val = "\(param.value)".urlEncoded
            parts.append("\(key)=\"\(val)\"")
        }

        return "OAuth " + parts.sorted().joined(separator: ", ")
    }

    mutating func sign(for url: URL, method: TwiHTTPMethod = .post, consumerSecret: String, oAuthTokenSecret: String? = nil, parameters: [String: String] = [:]) {
        let fullDictionary = dictionary.merging(parameters, uniquingKeysWith: { _, new in new })
        oauthSignature = SignatureComposer.compose(httpMethod: method.rawValue, url: url.absoluteString, params: fullDictionary, consumerSecret: consumerSecret, oAuthTokenSecret: oAuthTokenSecret)
    }
}
