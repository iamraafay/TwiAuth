//
//  CredentialsConfig.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-22.
//

import Foundation

public struct CredentialsConfig {
    let consumerKey: String
    let consumerSecret: String
    let callbackScheme: String

    public init(consumerKey: String, consumerSecret: String, callbackScheme: String) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.callbackScheme = callbackScheme + "://twiAuth"
    }
}
