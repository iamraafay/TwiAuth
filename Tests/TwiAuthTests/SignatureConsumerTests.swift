//
//  SignatureConsumerTests.swift
//  TwiAuth
//
//  Created by Mohammad Abdurraafay on 2021-01-31.
//

import XCTest
@testable import TwiAuth

final class SignatureConsumerTests: XCTestCase {
    func testConsumer() {
        let consumer = SignatureComposer.compose(httpMethod: "POST", url: "url", params: ["String" : "Any"], consumerSecret: "consumerSecret", oAuthTokenSecret: "oAuthTokenSecret")

        XCTAssertEqual(consumer, "hFHEdXu+dfOee75swjlEy9zjKdk=")
    }
}
