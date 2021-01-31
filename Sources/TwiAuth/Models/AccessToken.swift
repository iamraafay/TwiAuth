//
//  AccessToken.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-22.
//

import Foundation

public struct AccessToken: Codable, Equatable {
    public let oauthToken: String
    public let oauthSecret: String
    public let userId: String
    public let screenName: String

    public init(oauthToken: String, oauthSecret: String, userId: String, screenName: String) {
        self.oauthToken = oauthToken
        self.oauthSecret = oauthSecret
        self.userId = userId
        self.screenName = screenName
    }
}

extension AccessToken {
    init(with attributes: [String: String]) {
        oauthToken = attributes["oauth_token"] ?? ""
        oauthSecret = attributes["oauth_token_secret"] ?? ""
        userId = attributes["user_id"] ?? ""
        screenName = attributes["screen_name"] ?? ""
    }
}
