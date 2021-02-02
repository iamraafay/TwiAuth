//
//  TwiAuth.swift
//  TwiAuth
//
//  Copyright (c) 2020 Mohammad Abdurraafay

import Foundation
import AuthenticationServices
import Combine

public protocol TwiAuthTokenProviding {
    func read() -> AccessToken?
    func write(token: AccessToken)
}

public class TwiAuth {
    public var tokenProviding: TwiAuthTokenProviding? {
        didSet {
            guard let token = tokenProviding?.read() else { return }
            state = .accessToken(token)
        }
    }

    private var authenticatingPipeline: Cancellable?

    let session: URLSession
    let config: CredentialsConfig
    var state: State

    // MARK: Initializer.

    public init(consumerKey: String, consumerSecret: String, callbackScheme: String) {
        self.session = .shared
        self.config = CredentialsConfig(consumerKey: consumerKey, consumerSecret: consumerSecret, callbackScheme: callbackScheme)
        state = .idle
    }
}

public extension TwiAuth {
    func resetState() {
        state = .idle
    }

    func initialize(presentationContextProviding: ASWebAuthenticationPresentationContextProviding, prefersEphemeralWebBrowserSession: Bool = false, completion: @escaping (Result<AccessToken, TwiError>) -> Void) {
        if case .accessToken(let token) = state {
            completion(.success(token))
            return
        }

        let publisher = initializePublisher(
            presentationContextProviding: presentationContextProviding,
            prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
        )

        authenticatingPipeline = publisher.sink(receiveCompletion: { sinkCompletion in
            switch sinkCompletion {
            case .failure(let failure):
                completion(.failure(failure))
            case .finished:
                debugPrint("-- TwiAuth ended auth sequence -- ")
            }
        }, receiveValue: { [self] token in
            tokenProviding?.write(token: token)
            completion(.success(token))
        })
    }

    func initializePublisher(presentationContextProviding: ASWebAuthenticationPresentationContextProviding, prefersEphemeralWebBrowserSession: Bool = false) -> AnyPublisher<AccessToken, TwiError> {
        requestTokenPublisher()
            .flatMap { [self] _ in
                self.authenticatePublisher(with: presentationContextProviding, and: prefersEphemeralWebBrowserSession)
            }
            .flatMap { [self] _ in
                self.accessTokenPublisher()
            }
            .compactMap({ (state) -> AccessToken? in
                if case .accessToken(let token) = state {
                    return token
                }
                return nil
            })
            .mapError({ (publisher) -> TwiError in
                publisher
            })
            .eraseToAnyPublisher()
    }

    func accessTokenAuthHeader(method: String, url: URL, parameters: [String: String] = [:]) -> String {
        guard case let .accessToken(token) = state, let method = method.twiHTTPMethod else {
            return ""
        }

        return accessTokenHeader(method: method, url: url, token: token, parameters: parameters)
    }
}

extension String {
    var twiHTTPMethod: TwiHTTPMethod? {
        return TwiHTTPMethod(rawValue: self)
    }
}

public enum TwiError: Error {
    case badAuthData(String)
    case initialization(Error?), authenticating(Error?)
    case accessToken

    static func encodingError() -> NSError {
        NSError(domain: "com.twiauth.error", code: 601, userInfo: ["reason": "Failed to encode the response received."])
    }
}
