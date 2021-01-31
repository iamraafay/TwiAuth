//
//  TwiAuth+OAuthSequence.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-31.
//

import Foundation
import AuthenticationServices
import Combine

// MARK: OAuth Sequence helpers.
extension TwiAuth {
    func requestTokenPublisher() -> AnyPublisher<State, TwiError> {
        var request = URLRequest(url: Endpoint.requestToken.url, timeoutInterval: Double.infinity)
        request.httpMethod = TwiHTTPMethod.post.rawValue
        request.setValue(requestTokenHeader(), forHTTPHeaderField: "Authorization")
        return session.dataTaskPublisher(for: request)
            .tryMap { [self] result -> State in
                guard let dataString = String(data: result.data, encoding: .utf8) else { throw TwiError.encodingError() }
                guard let response = result.response as? HTTPURLResponse, response.statusCode == 200 else { throw TwiError.badAuthData(dataString) }

                let attributes = dataString.urlQueryStringParameters
                state = .requestedToken(RequestToken(with: attributes))
                return state
            }
            .mapError { error -> TwiError in
                .initialization(error)
            }
            .eraseToAnyPublisher()
    }

    func authenticatePublisher(with presentationContextProviding: ASWebAuthenticationPresentationContextProviding, and prefersEphemeralWebBrowserSession: Bool) -> AnyPublisher<State, TwiError> {
        guard case State.requestedToken(let token) = state else {
            return Fail(error: TwiError.authenticating(nil))
                .eraseToAnyPublisher()
        }

        return Future { [self] promise in
            let webAuthSession = ASWebAuthenticationSession(url: Endpoint.authenticate(token.oauthToken).url, callbackURLScheme: config.callbackScheme) { responseURL, error in
                guard error == nil else {
                    promise(.failure(.authenticating(error!)))
                    return
                }
                guard let parameters = responseURL?.query?.urlQueryStringParameters else {
                    promise(.failure(.authenticating(TwiError.encodingError())))
                    return
                }
                let token = AuthenticateToken(with: parameters)
                state = .authenticate(token)
                promise(.success(state))
            }
            webAuthSession.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
            webAuthSession.presentationContextProvider = presentationContextProviding

            DispatchQueue.main.async {
                webAuthSession.start()
            }
        }
        .eraseToAnyPublisher()
    }

    func accessTokenPublisher() -> AnyPublisher<State, TwiError> {
        guard case .authenticate(let token) = state else {
            return Fail(error: TwiError.accessToken)
                .eraseToAnyPublisher()
        }
        let authHeader = accessTokenVerifierHeader(
            oauthToken: token.oauthToken,
            oauthVerifier: token.oauthVerifier)
        var request = URLRequest(url: Endpoint.accessToken.url, timeoutInterval: Double.infinity)
        request.httpMethod = TwiHTTPMethod.post.rawValue
        request.setValue(authHeader, forHTTPHeaderField: "Authorization")

        return session.dataTaskPublisher(for: request)
            .tryMap { [self] result -> State in
                guard let dataString = String(data: result.data, encoding: .utf8) else { throw TwiError.encodingError() }
                guard let response = result.response as? HTTPURLResponse, response.statusCode == 200 else { throw TwiError.badAuthData(dataString) }

                let attributes = dataString.urlQueryStringParameters
                state = .accessToken(AccessToken(with: attributes))

                return state
            }
            .mapError { _ -> TwiError in
                .accessToken
            }
            .eraseToAnyPublisher()
    }
}

extension TwiAuth {
    enum State {
        case requestedToken(_ token: RequestToken)
        case authenticate(_ token: AuthenticateToken)
        case accessToken(_ token: AccessToken)
        case idle
    }

    struct RequestToken {
        let oauthToken: String
        let oauthSecret: String

        init(with attributes: [String: String]) {
            oauthToken = attributes["oauth_token"] ?? ""
            oauthSecret = attributes["oauth_token_secret"] ?? ""
        }
    }

    struct AuthenticateToken {
        let oauthToken: String
        let oauthVerifier: String

        init(with parameters: [String: String]) {
            oauthToken = parameters["oauth_token"] ?? ""
            oauthVerifier = parameters["oauth_verifier"] ?? ""
        }
    }
}
