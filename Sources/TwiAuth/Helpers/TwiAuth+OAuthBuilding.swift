//
//  TwiAuth+OAuthBuilding.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-31.
//

import Foundation

// MARK: OAuthToken building

public extension TwiAuth {

}

extension TwiAuth {
    func requestTokenHeader() -> String {
        var header = RequestTokenHeader(oauthCallback: config.callbackScheme, oauthConsumerKey: config.consumerKey)
        header.sign(for: Endpoint.requestToken.url, consumerSecret: config.consumerSecret)

        return header.authorized
    }

    func accessTokenVerifierHeader(oauthToken: String, oauthVerifier: String) -> String {
        var header = AccessTokenVerifierHeader(oauthConsumerKey: config.consumerKey, oauthToken: oauthToken, oauthVerifier: oauthVerifier)
        header.sign(for: Endpoint.accessToken.url, consumerSecret: config.consumerSecret)

        return header.authorized
    }

    func accessTokenHeader(method: TwiHTTPMethod, url: URL, token: AccessToken, parameters: [String: String] = [:]) -> String {
        var header = AccessTokenHeader(oauthConsumerKey: config.consumerKey, oauthToken: token.oauthToken)
        header.sign(for: url, method: method, consumerSecret: config.consumerSecret, oAuthTokenSecret: token.oauthSecret, parameters: parameters)

        let OAuthFinal = header.authorized
        debugPrint("OAuthFinal: \(OAuthFinal)")

        return OAuthFinal
    }
}
