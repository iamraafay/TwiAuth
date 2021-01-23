//
//  OAuthHeaderTests.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-23.
//

import XCTest
@testable import TwiAuth

final class OAuthHeaderTests: XCTestCase {

    func testCallingSignShouldPopulatesSignatureFieldForRequestTokenHeader() throws {
        var header = RequestTokenHeader(oauthCallback: "oauthCallback", oauthConsumerKey: "oauthConsumerKey")
        XCTAssertNil(header.oauthSignature)
        header.sign(for: Endpoint.requestToken.url, consumerSecret: "consumerSecret")
        XCTAssertNotNil(header.oauthSignature)
    }

    func testCallingSignShouldPopulatesSignatureFieldForAccessTokenVerifierHeader() throws {
        var header = AccessTokenVerifierHeader(oauthConsumerKey: "oauthConsumerKey", oauthToken: "oauthToken", oauthVerifier: "oauthVerifier")
        XCTAssertNil(header.oauthSignature)
        header.sign(for: Endpoint.requestToken.url, consumerSecret: "consumerSecret")
        XCTAssertNotNil(header.oauthSignature)
    }

    func testCallingSignShouldPopulatesSignatureFieldForAccessTokenHeaderHeader() throws {
        var header = AccessTokenHeader(oauthConsumerKey: "oauthConsumerKey", oauthToken: "oauthToken")
        XCTAssertNil(header.oauthSignature)
        header.sign(for: Endpoint.requestToken.url, consumerSecret: "consumerSecret")
        XCTAssertNotNil(header.oauthSignature)
    }

    func testAuthorizedString() throws {
        var header = AccessTokenHeader(oauthConsumerKey: "oauthConsumerKey", oauthToken: "oauthToken")
        header.sign(for: Endpoint.accessToken.url, consumerSecret: "consumerKey", oAuthTokenSecret: "oAuthTokenSecret")
        let authorized = header.authorized
        XCTAssertGreaterThan(authorized.count, .zero)
        /*
         "OAuth oauth_consumer_key=\"oauthConsumerKey\", oauth_nonce=\"40D53497-A474-48AA-A391-8C8040975438\", oauth_signature=\"HzS2uxYffl4w99gmf%2F7LW6FuEQ0%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1611424462\", oauth_token=\"oauthToken\", oauth_version=\"1.0\""
         */

        let firstSpacedIndex = try XCTUnwrap(authorized.firstIndex(of: " "))
        XCTAssertEqual(authorized[..<firstSpacedIndex], "OAuth")

        let parts = authorized[authorized.index(after: firstSpacedIndex)...].components(separatedBy: ", ")
        XCTAssertGreaterThan(parts.count, .zero)
        let partsDictionary: [[String: String]] = parts.map {
            let components = $0.components(separatedBy: "=")
            do  {
                let key = try XCTUnwrap(components.first, "No key found")
                let value = try XCTUnwrap(components.last, "No value found for key \(key)")

                return [key: value]
            } catch {
                XCTFail("Key & value could not be unwrapped \(error)")
                return ["": ""]
            }
        }

        XCTAssertGreaterThan(partsDictionary.count, .zero)
    }
}
