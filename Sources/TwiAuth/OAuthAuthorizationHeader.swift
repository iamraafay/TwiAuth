//
//  OAuthAuthorizationHeader.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2020-09-29.
//

import Foundation

protocol OAuthAuthorizationHeader: DictionaryRepresentable {
    var oauthConsumerKey: String { get }
    var oauthNonce: String { get }
    var oauthSignatureMethod: String { get }
    var oauthTimestamp: String { get }
    var oauthVersion: String { get }
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

struct AccessTokenVerifierHeader: OAuthAuthorizationHeader {
    let oauthConsumerKey: String
    let oauthToken: String
    let oauthVerifier: String
    let oauthNonce: String = UUID().uuidString
    let oauthSignatureMethod: String = "HMAC-SHA1"
    let oauthTimestamp: String = String(Int(NSDate().timeIntervalSince1970))
    let oauthVersion: String = "1.0"
}

struct SignedAccessTokenVerifierHeader: SignedHeader, OAuthAuthorizationHeader {
    let oauthSignature: String
    let oauthConsumerKey: String
    let oauthToken: String
    let oauthVerifier: String
    let oauthNonce: String
    let oauthSignatureMethod: String
    let oauthTimestamp: String
    let oauthVersion: String
}

extension SignedAccessTokenVerifierHeader {
    init(requestToken header: AccessTokenVerifierHeader, oauthSignature: String) {
        self.oauthSignature = oauthSignature
        oauthToken = header.oauthToken
        oauthVerifier = header.oauthVerifier
        oauthConsumerKey = header.oauthConsumerKey
        oauthNonce = header.oauthNonce
        oauthSignatureMethod = header.oauthSignatureMethod
        oauthTimestamp = header.oauthTimestamp
        oauthVersion = header.oauthVersion
    }
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
struct AccessTokenHeader: OAuthAuthorizationHeader {
    let oauthConsumerKey: String
    let oauthNonce: String = UUID().uuidString
    let oauthSignatureMethod: String = "HMAC-SHA1"
    let oauthTimestamp: String = String(Int(NSDate().timeIntervalSince1970))
    let oauthToken: String
    let oauthVersion: String = "1.0"
}

struct SignedAccessTokenHeader: SignedHeader, OAuthAuthorizationHeader {
    let oauthSignature: String
    let oauthConsumerKey: String
    let oauthToken: String
    let oauthNonce: String
    let oauthSignatureMethod: String
    let oauthTimestamp: String
    let oauthVersion: String
}

extension SignedAccessTokenHeader {
    init(requestToken header: AccessTokenHeader, oauthSignature: String) {
        self.oauthSignature = oauthSignature
        oauthToken = header.oauthToken
        oauthConsumerKey = header.oauthConsumerKey
        oauthNonce = header.oauthNonce
        oauthSignatureMethod = header.oauthSignatureMethod
        oauthTimestamp = header.oauthTimestamp
        oauthVersion = header.oauthVersion
    }
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
