//
//  OAuthHeaderBuilder.swift
//  TwiAuth
//
//  Copyright (c) 2020 Mohammad Abdurraafay

import Foundation

struct OAuthHeaderBuilder {
    let config: CredentialsConfig
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

    func accessTokenHeader(url: URL, method: TwiHTTPMethod, token: AccessToken) -> String {
        var header = AccessTokenHeader(oauthConsumerKey: config.consumerKey, oauthToken: token.oauthToken)
        header.sign(for: url, method: method, consumerSecret: config.consumerSecret, oAuthTokenSecret: token.oauthSecret)

        return header.authorized
    }
}
