//
//  OAuthTokenSequence.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2020-09-27.
//

import Foundation
import AuthenticationServices

struct RequestOAuthTokenInput {
  let consumerKey = ""
  let consumerSecret = ""
  let callbackScheme = "oauth-swift"
}

struct RequestOAuthTokenResponse {
  let oauthToken: String
  let oauthTokenSecret: String
  let oauthCallbackConfirmed: String
}

enum TwitterURL {
    private var components: URLComponents {
        var urlComponents = URLComponents()
        urlComponents.scheme = "https"
        urlComponents.host = "api.twitter.com"

        return urlComponents
    }

    case requestToken, authenticate(_ requestToken: String), accessToken

    var url: URL {
        var buildingComponents = components
        switch self {
        case .requestToken:
            buildingComponents.path = "/oauth/request_token"

            return buildingComponents.url!
        case .authenticate(requestToken: let requestToken):
            buildingComponents.path = "/oauth/authenticate"
            buildingComponents.queryItems = [URLQueryItem(name: "oauth_token", value: requestToken)]

            return buildingComponents.url!
        case .accessToken:
            buildingComponents.path = "/oauth/access_token"

            return buildingComponents.url!
        }
    }
}

class OAuthTokenSequence {
    let urlSession: URLSession
    let oAuth: OAuthHeaderBuilder

    private(set) var accessToken: String?

    weak var presentationContextProviding: ASWebAuthenticationPresentationContextProviding?

    init(urlSession: URLSession = .shared, oAuth: OAuthHeaderBuilder = OAuthHeaderBuilder()) {
        self.urlSession = urlSession
        self.oAuth = oAuth
    }

    func initialize(completion: @escaping (Result<String, Error>) -> Void) {
        let request = RequestOAuthTokenInput()
        requestToken(args: request) { [weak self] result in
            guard let self = self else { return }
            let authSession = self.asWebAuthentication(requestToken: result.oauthToken) { [weak self] token, verifier in
                guard let self = self else {  return }
                print(token ?? "no token..")
                print(verifier ?? "no verifier..")
                guard let token = token, let verifier = verifier else { return }
                let finalRequest = RequestAccessTokenInput(requestToken: token, requestTokenSecret: result.oauthTokenSecret, oauthVerifier: verifier)
                self.requestAccessToken(args: finalRequest) { [weak self ]finalResponse in
                    self?.accessToken = finalResponse.accessToken
                    if let accessToken = self?.accessToken {
                        completion(.success(accessToken))
                    } else {
                        completion(.failure(NSError(domain: "com.oauth.error", code: 999, userInfo: nil)))
                    }
                }
            }

            DispatchQueue.main.async {
                authSession.start()
            }
        }
    }

    func requestToken(args: RequestOAuthTokenInput, _ complete: @escaping (RequestOAuthTokenResponse) -> Void) {
        let urlString = "https://api.twitter.com/oauth/request_token"
        let callback = args.callbackScheme + "://success"
        var params: [String: Any] = [
            "oauth_callback": callback,
            "oauth_consumer_key": args.consumerKey,
            "oauth_nonce": UUID().uuidString, // nonce can be any 32-bit string made up of random ASCII values
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": String(Int(NSDate().timeIntervalSince1970)),
            "oauth_version": "1.0"
        ]

        // Build the OAuth Signature from Parameters
        params["oauth_signature"] = oAuth.composeSignature(url: urlString, params: params, consumerSecret: args.consumerSecret)

        // Once OAuth Signature is included in our parameters, build the authorization header
        let authHeader = oAuth.authorizationHeader(params: params)
        var request = URLRequest(url: URL(string: urlString)!, timeoutInterval: Double.infinity)
        request.httpMethod = "POST"
        request.setValue(authHeader, forHTTPHeaderField: "Authorization")


//        request.addValue("OAuth oauth_consumer_key=\"xTErQkXWXheazyJc95YiqL8Gm\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"1601159038\",oauth_nonce=\"q4zwrZKXgL0\",oauth_version=\"1.0\",oauth_signature=\"xmt%2Ft8l1ascczRXbBq8vyPh%2BXqo%3D\"", forHTTPHeaderField: "Authorization")
//        request.addValue("personalization_id=\"v1_CsLPBiwYD4FhSI37YCHZKg==\"; guest_id=v1%3A160115581238979484", forHTTPHeaderField: "Cookie")


        let task = urlSession.dataTask(with: request) { data, response, error in
            guard let data = data else { return }
            print("textEncodingName: \(response?.textEncodingName)")
            guard let dataString = String(data: data, encoding: .utf8) else { return }
            // dataString should return: oauth_token=XXXX&oauth_token_secret=YYYY&oauth_callback_confirmed=true
            let attributes = dataString.urlQueryStringParameters
            let result = RequestOAuthTokenResponse(oauthToken: attributes["oauth_token"] ?? "", oauthTokenSecret: attributes["oauth_token_secret"] ?? "", oauthCallbackConfirmed: attributes["oauth_callback_confirmed"] ?? "")
            complete(result)
        }

        task.resume()
    }

    func asWebAuthentication(requestToken: String, completion: @escaping (_ token: String?, _ verifier: String?) -> Void) -> ASWebAuthenticationSession {
        //oauth_token=luNrVAAAAAABHNdeAAABdMyEBAs&oauth_token_secret=kWp6ZqQZb5tTBhoAZhgVv82i2Y8ZHMfC&oauth_callback_confirmed=true
//        let requestToken = "luNrVAAAAAABHNdeAAABdMyEBAs"
        //let authorizedOAuthToken = "oauth_token=luNrVAAAAAABHNdeAAABdMyEBAs&oauth_verifier=j9ilJ2klEkCbFnSgm992Yl4ALtkbXYKz"
        //oauth_token=20425606-pGCZS22EDdHvHYQkVtc6akmW2VIMenOueCX3Pm5sG&oauth_token_secret=VAhraWOvS8WhfYI56U8nwcCszwZWwPG3EQz1bSkhzs2M2&user_id=20425606&screen_name=mohdabdurraafay

//        let url = URL(string: "https://api.twitter.com/oauth/authenticate?oauth_token=\(requestToken)")!
        let url = TwitterURL.authenticate(requestToken).url
        let authSession = ASWebAuthenticationSession(url: url, callbackURLScheme: "oauth-swift://oauth-callback/twitter") { url, error in

            print("URL: \(String(describing: url))")

            guard let parameters = url?.query?.urlQueryStringParameters else { return }
            /*
            url => twittersdk://success?oauth_token=XXXX&oauth_verifier=ZZZZ
            url.query => oauth_token=XXXX&oauth_verifier=ZZZZ
            url.query?.urlQueryStringParameters => ["oauth_token": "XXXX", "oauth_verifier": "YYYY"]
            */
            guard let token = parameters["oauth_token"], let verifier = parameters["oauth_verifier"] else { return }

            //TODO: Handle error
            print("Error: \(String(describing: error))")

            completion(token, verifier)
        }
        authSession.prefersEphemeralWebBrowserSession = true
        authSession.presentationContextProvider = presentationContextProviding

        return authSession
    }

    struct RequestAccessTokenInput {
        let consumerKey = "xTErQkXWXheazyJc95YiqL8Gm"
        let consumerSecret = "8DCEbumrcPzNWq5htUUDPx9CbYL2IBErrZiXwNxYKBuWIzTOMr"
      let requestToken: String // = RequestOAuthTokenResponse.oauthToken
      let requestTokenSecret: String // = RequestOAuthTokenResponse.oauthTokenSecret
      let oauthVerifier: String
    }
    struct RequestAccessTokenResponse {
      let accessToken: String
      let accessTokenSecret: String
      let userId: String
      let screenName: String
    }

    func requestAccessToken(args: RequestAccessTokenInput,
                            _ complete: @escaping (RequestAccessTokenResponse) -> Void) {

        let request = (url: "https://api.twitter.com/oauth/access_token", httpMethod: TwiHTTPMethod.post)

      var params: [String: Any] = [
        "oauth_token" : args.requestToken,
        "oauth_verifier" : args.oauthVerifier,
        "oauth_consumer_key" : args.consumerKey,
        "oauth_nonce" : UUID().uuidString, // nonce can be any 32-bit string made up of random ASCII values
        "oauth_signature_method" : "HMAC-SHA1",
        "oauth_timestamp" : String(Int(NSDate().timeIntervalSince1970)),
        "oauth_version" : "1.0"
      ]

      // Build the OAuth Signature from Parameters
        params["oauth_signature"] = oAuth.composeSignature(httpMethod: request.httpMethod, url: request.url, params: params, consumerSecret: args.consumerSecret, oAuthTokenSecret: args.requestTokenSecret)

      // Once OAuth Signature is included in our parameters, build the authorization header
        let authHeader = oAuth.authorizationHeader(params: params)

      guard let url = URL(string: request.url) else { return }
      var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = request.httpMethod.rawValue
      urlRequest.setValue(authHeader, forHTTPHeaderField: "Authorization")
      let task = URLSession.shared.dataTask(with: urlRequest) { (data, response, error) in
        guard let data = data else { return }
        guard let dataString = String(data: data, encoding: .utf8) else { return }
        let attributes = dataString.urlQueryStringParameters
        let result = RequestAccessTokenResponse(accessToken: attributes["oauth_token"] ?? "",
                                                accessTokenSecret: attributes["oauth_token_secret"] ?? "",
                                                userId: attributes["user_id"] ?? "",
                                                screenName: attributes["screen_name"] ?? "")
        complete(result)
      }
      task.resume()
    }
}
