//
//  Endpoint.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-22.
//

import Foundation

enum Endpoint {
    case requestToken
    case authenticate(_ requestToken: String)
    case accessToken
}

extension Endpoint {
    private var components: URLComponents {
        var urlComponents = URLComponents()
        urlComponents.scheme = "https"
        urlComponents.host = "api.twitter.com"

        return urlComponents
    }

    var url: URL {
        var buildingComponents = components
        switch self {
        case .requestToken:
            buildingComponents.path = "/oauth/request_token"

            return buildingComponents.url!
        case .authenticate(requestToken: let requestToken):
            buildingComponents.path = "/oauth/authorize"
            buildingComponents.queryItems = [URLQueryItem(name: "oauth_token", value: requestToken)]

            return buildingComponents.url!
        case .accessToken:
            buildingComponents.path = "/oauth/access_token"

            return buildingComponents.url!
        }
    }
}

enum TwiHTTPMethod: String, Equatable {
    case get = "GET", post = "POST"
}
