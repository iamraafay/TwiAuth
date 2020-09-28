
import AuthenticationServices

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
    enum State {
        case requestedToken(_ token: RequestToken), authenticating, accessToken(String), idle
    }

    private let session: URLSession
    private let config: Config
    private let sequence: OAuthTokenSequence
    private var state: State

    public weak var presentationContextProviding: ASWebAuthenticationPresentationContextProviding? {
        didSet {
            sequence.presentationContextProviding = presentationContextProviding
        }
    }

    private(set) var token: String?

    public init(session: URLSession = .shared, config: Config) {
        self.session = session
        self.config = config
        sequence = OAuthTokenSequence()
        state = .idle
    }

    public func initialize(completion: @escaping (Result<String, Error>) -> Void) {
        guard presentationContextProviding != nil else {
            fatalError("Please set `presentationContextProviding` in order for `AuthenticationService` to present Safari on a provided window.")
        }

        /// WIP
//        requestToken { result in
//            switch result {
//            case .success(let state):
//                print(state)
//            case .failure(let error):
//                print(error)
//            }
//        }
//
//        return

        let request = RequestOAuthTokenInput()
        sequence.requestToken(args: request) { [weak self] response in
            guard let self = self else { return }
                let asSession = self.sequence.asWebAuthentication(requestToken: response.oauthToken) { token, verifier in
                    guard let token = token, let verifier = verifier else {
                        fatalError("no token and verifier...")
                    }
                    self.sequence.requestAccessToken(args: OAuthTokenSequence.RequestAccessTokenInput(requestToken: token, requestTokenSecret: response.oauthTokenSecret, oauthVerifier: verifier)) { accessTokenResponse in
                        completion(.success(accessTokenResponse.accessToken))
                    }
                }
                DispatchQueue.main.async {
                    asSession.start()
                }
        }
    }

    private func requestToken(completion: @escaping (Result<State, TwiError>) -> Void) {
        let headerBuilder = OAuthHeaderBuilder()
        let authHeader = headerBuilder.requestTokenHeader(with: config.consumerKey, config.consumerSecret, and: config.callbackScheme)
        var request = URLRequest(url: TwitterURL.requestToken.url, timeoutInterval: Double.infinity)
        request.httpMethod = TwiHTTPMethod.post.rawValue
        request.setValue(authHeader, forHTTPHeaderField: "Authorization")
        session.dataTask(with: request) { [weak self] data, response, error in
            guard let self = self else { return }
            guard let data = data else { completion(.failure(.initialization(error))); return }
            guard let dataString = String(data: data, encoding: .utf8) else {
                completion(.failure(.initialization(TwiError.encodingError()))); return }
            guard let response = response as? HTTPURLResponse, response.statusCode == 200 else { completion(.failure(.badAuthData(dataString))); return }
            let attributes = dataString.urlQueryStringParameters
            self.state = .requestedToken(RequestToken(with: attributes))
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

public enum TwiError: Error {
    case badAuthData(String)
    case initialization(Error?), authenticating(Error)

    static func encodingError() -> NSError {
        NSError(domain: "com.twiauth.error", code: 601, userInfo: ["reason": "Failed to encode the response received."])
    }
}
