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
    public var prefersEphemeralWebBrowserSession: Bool
    public weak var presentationContextProviding: ASWebAuthenticationPresentationContextProviding?
    public var tokenProviding: TwiAuthTokenProviding? {
        didSet {
            guard let token = tokenProviding?.read() else { return }
            state = .accessToken(token)
        }
    }

    private let session: URLSession
    private let config: CredentialsConfig
    private let headerBuilder: OAuthHeaderBuilder

    private var state: State
    private var authenticatingPipeline: Cancellable?

    private(set) var token: String?

    public init(session: URLSession = .shared, config: CredentialsConfig) {
        self.session = session
        self.config = config
        headerBuilder = OAuthHeaderBuilder(config: config)
        prefersEphemeralWebBrowserSession = false
        state = .idle
    }

    public func resetState() {
        state = .idle
    }

    public func initialize(completion: @escaping (Result<AccessToken, TwiError>) -> Void) {
        if case .accessToken(let token) = state {
            completion(.success(token))
            return
        }
        guard presentationContextProviding != nil else {
            fatalError("Please set `presentationContextProviding` in order for `AuthenticationService` to present Safari on a provided window.")
        }

        let publisher = initializePublisher()

        authenticatingPipeline = publisher.sink(receiveCompletion: { sinkCompletion in
            switch sinkCompletion {
            case .failure(let failure):
                completion(.failure(failure))
            case .finished:
                debugPrint("-- TwiAuth ended auth sequence -- ")
            }
        }, receiveValue: { [self] state in
            guard case let .accessToken(token) = state else {
                completion(.failure(.accessToken))
                return
            }
            tokenProviding?.write(token: token)
            completion(.success(token))
        })
    }

    func initializePublisher() -> AnyPublisher<State, TwiError> {
        requestTokenPublisher()
            .flatMap { [self] _ in
                self.authenticatePublisher()
            }
            .flatMap { _ in
                self.accessTokenPublisher()
            }
            .eraseToAnyPublisher()
    }

    private func requestTokenPublisher() -> AnyPublisher<State, TwiError> {
        let authHeader = headerBuilder.requestTokenHeader()
        var request = URLRequest(url: Endpoint.requestToken.url, timeoutInterval: Double.infinity)
        request.httpMethod = TwiHTTPMethod.post.rawValue
        request.setValue(authHeader, forHTTPHeaderField: "Authorization")
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

    private func authenticatePublisher() -> AnyPublisher<State, TwiError> {
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

    private func accessTokenPublisher() -> AnyPublisher<State, TwiError> {
        guard case .authenticate(let token) = state else {
            return Fail(error: TwiError.accessToken)
                .eraseToAnyPublisher()
        }
        let authHeader = headerBuilder.accessTokenVerifierHeader(
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

    @available(*, deprecated, renamed: "requestTokenPublisher")
    private func requestToken(completion: @escaping (Result<State, TwiError>) -> Void) {
        let authHeader = headerBuilder.requestTokenHeader()
        var request = URLRequest(url: Endpoint.requestToken.url, timeoutInterval: Double.infinity)
        request.httpMethod = TwiHTTPMethod.post.rawValue
        request.setValue(authHeader, forHTTPHeaderField: "Authorization")
        session.dataTask(with: request) { [weak self] data, response, error in
            guard let self = self else { return }
            guard let data = data else {
                completion(.failure(.initialization(error)))
                return
            }
            guard let dataString = String(data: data, encoding: .utf8) else {
                completion(.failure(.initialization(TwiError.encodingError())));
                return
            }
            guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                completion(.failure(.badAuthData(dataString)))
                return
            }

            let attributes = dataString.urlQueryStringParameters
            self.state = .requestedToken(RequestToken(with: attributes))
            completion(.success(self.state))

        }.resume()
    }

    @available(*, deprecated, renamed: "authenticatePublisher")
    private func authenticate(completion: @escaping (Result<State, TwiError>) -> Void) {
        guard case State.requestedToken(let token) = state else { return }
        let asSession = ASWebAuthenticationSession(url: Endpoint.authenticate(token.oauthToken).url, callbackURLScheme: config.callbackScheme) { responseURL, error in
            guard error == nil else {
                completion(.failure(.authenticating(error!)))
                return
            }
            guard let parameters = responseURL?.query?.urlQueryStringParameters else {
                completion(.failure(.authenticating(TwiError.encodingError())))
                return
            }
            let token = AuthenticateToken(with: parameters)
            self.state = .authenticate(token)
            completion(.success(self.state))
        }

        asSession.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
        asSession.presentationContextProvider = presentationContextProviding

        DispatchQueue.main.async {
            asSession.start()
        }
    }

    @available(*, deprecated, renamed: "accessTokenPublisher")
    private func accessToken(completion: @escaping (Result<State, TwiError>) -> Void) {
        guard case .authenticate(let token) = state else {
            return
        }
        let authHeader = headerBuilder.accessTokenVerifierHeader(
            oauthToken: token.oauthToken,
            oauthVerifier: token.oauthVerifier)
        var request = URLRequest(url: Endpoint.accessToken.url, timeoutInterval: Double.infinity)
        request.httpMethod = TwiHTTPMethod.post.rawValue
        request.setValue(authHeader, forHTTPHeaderField: "Authorization")
        session.dataTask(with: request) { [weak self] data, response, error in
            guard let self = self else { return }
            guard let data = data else {
                completion(.failure(.initialization(error)))
                return
            }
            guard let dataString = String(data: data, encoding: .utf8) else {
                completion(.failure(.initialization(TwiError.encodingError())));
                return
            }
            guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                completion(.failure(.badAuthData(dataString)))
                return
            }

            let attributes = dataString.urlQueryStringParameters
            let token = AccessToken(with: attributes)
            self.state = .accessToken(token)
            completion(.success(self.state))

        }.resume()
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

public extension TwiAuth {
    func accessTokenAuthHeader(url: URL, method: String) -> String {
        guard case let .accessToken(token) = state else {
            return ""
        }

        guard let method = method.twiHTTPMethod else {
            return ""
        }

        let authHeader = headerBuilder.accessTokenHeader(url: url, method: method, token: token)

        return authHeader
    }
}

extension String {
    var twiHTTPMethod: TwiHTTPMethod? {
        return TwiHTTPMethod(rawValue: self)
    }
}

public extension URLRequest {
    mutating func authorize(with twiAuth: TwiAuth) {
        guard
            let url = url,
            let httpMethod = httpMethod else {
            return
        }
        addValue(twiAuth.accessTokenAuthHeader(url: url, method: httpMethod), forHTTPHeaderField: "Authorization")
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
