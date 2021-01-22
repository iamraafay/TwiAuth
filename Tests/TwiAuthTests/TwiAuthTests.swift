import XCTest
@testable import TwiAuth

final class TwiAuthTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        //XCTAssert("Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}

final class OAuthHeaderBuilderTests: XCTestCase {
    private var builder: OAuthHeaderBuilder!

    private let consumerKey = "consumerKey"
    private let consumerSecret = "consumerSecret"
    private let callback = "callback"

    override func setUp() {
        builder = OAuthHeaderBuilder()
    }

    func testRequestTokenHeader() {
        let header = builder.requestTokenHeader(consumerKey: consumerKey, consumerSecret: consumerSecret, callback: callback)
        debugPrint("header:  \(header)")
        XCTAssertNotEqual(header.count, .zero)
    }
}

class OAuthHeaderTests: XCTestCase {
    func testCallingSignPopulatesSignatureField() {

    }

    func testAuthorizedString() {
        
    }

    func testCallingAuthorizedDoesNotProceedWithoutSignature() {

    }

    func testRequestTokenHeaderDictionary() throws {
        let header = RequestTokenHeader(oauthCallback: "oauthCallback", oauthConsumerKey: "oauthConsumerKey")

        let oauthConsumerKey = try XCTUnwrap(header.dictionary["oauthConsumerKey"]) as? String
        XCTAssertEqual(oauthConsumerKey, header.oauthConsumerKey)

        let oauthCallback = try XCTUnwrap(header.dictionary["oauthCallback"]) as? String
        XCTAssertEqual(oauthCallback, header.oauthCallback)
    }

    func testSignedRequestHeaderToken() {
        

    }
}
