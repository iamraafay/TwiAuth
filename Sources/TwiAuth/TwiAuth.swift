
import AuthenticationServices
import Combine

public struct AccessToken {
    let oauthToken: String
    let oauthSecret: String
    let userId: String
    let screenName: String
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

    private(set) var token: String?

    public init(session: URLSession = .shared, config: Config) {
        self.session = session
        self.config = config
        prefersEphemeralWebBrowserSession = false
        sequence = OAuthTokenSequence()
        state = .idle
    }

    public func initialize(completion: @escaping (Result<AccessToken, TwiError>) -> Void) {
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
        }, receiveValue: { state in
            guard case let State.accessToken(accessToken) = state else {
                completion(.failure(.accessToken))
                return
            }
            completion(.success(accessToken))
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
        let authHeader = headerBuilder.accessTokenHeader(
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
