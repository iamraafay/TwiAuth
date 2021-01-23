//
//  Mocks.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-23.
//

import Foundation
@testable import TwiAuth

struct HeaderMock: OAuthHeader {
    let stub: Stub
    class Stub: Encodable {
        typealias SignFuncCallback = ((_ url: URL, _ method: TwiHTTPMethod, _ consumerSecret: String, _ oAuthTokenSecret: String?) -> Void)
        private(set) var signForURLMethodConsumerSecretOAuthTokenSecret: SignFuncCallback?
        init(signForURLMethodConsumerSecretOAuthTokenSecret: @escaping SignFuncCallback) {
            self.signForURLMethodConsumerSecretOAuthTokenSecret = signForURLMethodConsumerSecretOAuthTokenSecret
        }

        func encode(to encoder: Encoder) throws {
            signForURLMethodConsumerSecretOAuthTokenSecret = nil
        }
    }
    var oauthSignature: String?
    var oauthConsumerKey: String
    var oauthNonce: String
    var oauthSignatureMethod: String
    var oauthTimestamp: String
    var oauthVersion: String

    init(stub: Stub) {
        self.oauthSignature = "oauthSignature"
        self.oauthConsumerKey = "oauthConsumerKey"
        self.oauthNonce = "oauthNonce"
        self.oauthSignatureMethod = "oauthSignatureMethod"
        self.oauthTimestamp = "oauthTimestamp"
        self.oauthVersion = "oauthVersion"
        self.stub = stub
    }


    mutating func sign(for url: URL, method: TwiHTTPMethod, consumerSecret: String, oAuthTokenSecret: String?) {
        stub.signForURLMethodConsumerSecretOAuthTokenSecret!(url, method, consumerSecret, oAuthTokenSecret)
    }
}
