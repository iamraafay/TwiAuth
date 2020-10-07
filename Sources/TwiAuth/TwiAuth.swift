
import AuthenticationServices
import Combine

public protocol TwiAuthTokenProviding {
    func read() -> AccessToken?
    func write(token: AccessToken)
}

public struct AccessToken: Codable {
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

public struct Config {
    let consumerKey: String
    let consumerSecret: String
    let callbackScheme: String

    public init(consumerKey: String, consumerSecret: String, callbackScheme: String) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.callbackScheme = callbackScheme + "://twiAuth"
    }
}

public class TwiAuth {
    struct RequestToken {
        let oauthToken: String
        let oauthSecret: String
    }

    struct AuthenticateToken {
        let oauthToken: String
        let oauthVerifier: String
    }

    enum State {
        case requestedToken(_ token: RequestToken), authenticate(_ token: AuthenticateToken), accessToken(_ token: AccessToken), idle
    }

    private let session: URLSession
    private let config: Config
    private let sequence: OAuthTokenSequence
    private var state: State

    private var authenticatingPipeline: Cancellable?

    public var prefersEphemeralWebBrowserSession: Bool
    public weak var presentationContextProviding: ASWebAuthenticationPresentationContextProviding? {
        didSet {
            sequence.presentationContextProviding = presentationContextProviding
        }
    }
    public var tokenProviding: TwiAuthTokenProviding? {
        didSet {
            guard let token = tokenProviding?.read() else { return }
            state = .accessToken(token)
        }
    }

    private(set) var token: String?

    public init(session: URLSession = .shared, config: Config) {
        self.session = session
        self.config = config
        prefersEphemeralWebBrowserSession = false
        sequence = OAuthTokenSequence()
        state = .idle
    }

    public func initialize(completion: @escaping (Result<Bool, TwiError>) -> Void) {
        if case .accessToken = state {
            completion(.success(true))
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
            completion(.success(true))
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
        Future { [weak self] promise in
            self?.requestToken { result in
                switch result {
                case .success(let state):
                    promise(.success(state))
                case .failure(let error):
                    promise(.failure(error))
                }
            }
        }
        .eraseToAnyPublisher()
    }

    private func authenticatePublisher() -> AnyPublisher<State, TwiError> {
        Future { [weak self] promise in
            self?.authenticate { result in
                switch result {
                case .success(let state):
                    promise(.success(state))
                case .failure(let error):
                    promise(.failure(error))
                }
            }
        }
        .eraseToAnyPublisher()
    }

    private func accessTokenPublisher() -> AnyPublisher<State, TwiError> {
        Future { [weak self] promise in
            self?.accessToken { result in
                switch result {
                case .success(let state):
                    promise(.success(state))
                case .failure(let error):
                    promise(.failure(error))
                }
            }
        }
        .eraseToAnyPublisher()
    }

    private func requestToken(completion: @escaping (Result<State, TwiError>) -> Void) {
        let headerBuilder = OAuthHeaderBuilder()
        let authHeader = headerBuilder.requestTokenHeader(with: config.consumerKey, config.consumerSecret, and: config.callbackScheme)
        var request = URLRequest(url: TwitterURL.requestToken.url, timeoutInterval: Double.infinity)
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

    private func authenticate(completion: @escaping (Result<State, TwiError>) -> Void) {
        guard case State.requestedToken(let token) = state else { return }
        let asSession = ASWebAuthenticationSession(url: TwitterURL.authenticate(token.oauthToken).url, callbackURLScheme: config.callbackScheme) { responseURL, error in
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

    private func accessToken(completion: @escaping (Result<State, TwiError>) -> Void) {
        guard case .authenticate(let token) = state else {
            return
        }
        let headerBuilder = OAuthHeaderBuilder()
        let authHeader = headerBuilder.accessTokenVerifierHeader(
            with: config.consumerKey,
            oauthToken: token.oauthToken,
            oauthVerifier: token.oauthVerifier,
            config.consumerSecret, and: config.callbackScheme)
        var request = URLRequest(url: TwitterURL.accessToken.url, timeoutInterval: Double.infinity)
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

extension TwiAuth.RequestToken {
    init(with attributes: [String: String]) {
        oauthToken = attributes["oauth_token"] ?? ""
        oauthSecret = attributes["oauth_token_secret"] ?? ""
    }
}

extension TwiAuth.AuthenticateToken {
    init(with parameters: [String: String]) {
        oauthToken = parameters["oauth_token"] ?? ""
        oauthVerifier = parameters["oauth_verifier"] ?? ""
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

public enum TwiError: Error {
    case badAuthData(String)
    case initialization(Error?), authenticating(Error)
    case accessToken

    static func encodingError() -> NSError {
        NSError(domain: "com.twiauth.error", code: 601, userInfo: ["reason": "Failed to encode the response received."])
    }
}

extension TwiAuth {
    func accessTokenAuthHeader(url: String, method: TwiHTTPMethod) -> String {
        guard case let .accessToken(token) = state else {
            return ""
        }

        let authHeader = OAuthHeaderBuilder().accessTokenHeader(url: url, method: .get, consumerKey: config.consumerKey, consumerSecret: config.consumerSecret, oauthToken: token.oauthToken, oauthSecret: token.oauthSecret)

        return authHeader
    }
}

public extension URLRequest {
    mutating func authorize(with twiAuth: TwiAuth) {
        guard
            let urlString = url?.absoluteString,
            let httpMethod = httpMethod,
            let method = TwiHTTPMethod(rawValue: httpMethod) else {
            return
        }
        addValue(twiAuth.accessTokenAuthHeader(url: urlString, method: method), forHTTPHeaderField: "Authorization")
    }
}
