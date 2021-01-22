# 🦉 TwiAuth 💫

Twitter OAuth made simple for iOS using `ASWebAuthenticationSession`. 🕵🏽‍♀️  
  
# Installing in your Xcode Project  
  - Head to your scheme on Xcode and select Swift Package Manger.
  - Copy/Paste the URL of the TwiAuth repo and proceed to install the latest version or master, as desire.


# Usage
### Configuration & Setup

Let's see how it fits with your `ViewController`.  
```  
class ViewController: UIViewController {
	let twiAuth
	init(nibName nibNameOrNil: String?, bundle nibBundleOrNil: Bundle?) {
		  let config = CredentialsConfig(
            consumerKey: "consumer-key",
            consumerSecret: "consumer-secret",
            callbackScheme: "callback-scheme"
        )
			twiAuth = TwiAuth(config: config)
			super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
	}
}
```

This is how it looks as base setup. But this isn't functional yet. Since TwiAuth uses `ASWebAuthenticationSession` under the hood, it requires the authorization the user via its own view controller that needs to be presented on a provided window. Let's look at how we can configure `ASWebAuthenticationPresentationContextProviding`.

```
class ViewController: UIViewController {
	let twiAuth
	init(nibName nibNameOrNil: String?, bundle nibBundleOrNil: Bundle?) {
			....
			super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
			// Sets the presentation context.
			twiAuth.presentationContextProviding = self
	}
}
	
extention ViewController: ASWebAuthenticationPresentationContextProviding {
	    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return view.window!
    }
}
```

### Token Providing
TwitAuth comes with a handy `TwiAuthTokenProviding` protocol for convenience to write and read token wherever you app decides to store them.  
  
This convenience would allow TwiAuth to read an existing token and respond back instead to generating a new one. Let' see how we can confirm to this.  
  
```
class ViewController: UIViewController {
	let twiAuth
	init(nibName nibNameOrNil: String?, bundle nibBundleOrNil: Bundle?) {
			....
			super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
			// TwiAuthTokenProviding conformance.
			twiAuth.tokenProviding = self
	}
}

extension ViewController: TwiAuthTokenProviding {
    func read() -> AccessToken? {
        try? keychain.retrieve()
    }

    func write(token: AccessToken) {
        do {
            try keychain.save(token: token)
        } catch {
            debugPrint("error while saving token: \(error)")
        }
    }
}
```

### Authorizing your Requests
If you plan to let the TwitAuth know about previously generated token via providing protocol, then you could simply sign you `URLRequests` as follows.  
  
```
	let request = URLRequest(..)
	request.authorize(with: twiAuth)
	...
```

or else, you could always request TwitAuth to provide the authorization header String so your client can directly sign the  request themselves.  
  
```
let oauthHeader = twiAuth.accessTokenAuthHeader(url: url, method: method)

var request = URLRequest(url: endpoint.url)
request.addValue(oauthHeader, forHTTPHeaderField: "Authorization")
```

✨ Happy Hacking with Twitter Api! 👨🏽‍💻 👨🏽‍🎨