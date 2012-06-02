var express = require('express');
var oauth = require('../../lib').Client;

var app = express.createServer();

var client = oauth.createClient(oauth.Version.OAUTH1, {
	consumerKey: 'fNRoVPyBJpgrtrXrIx6Og',
	consumerSecret: 'yd3O5lvux87WHVidnNg2SE7yk8pecWZFZaaspYeSZQ',
	requestURL: 'https://twitter.com/oauth/request_token',
	accessURL: 'https://twitter.com/oauth/access_token',
	signatureMethod: oauth.Signature.HMACSHA1,
	callback: 'http://127.0.0.1:8000/callback',
	headers: {}
});

app.get('/', function(req, res) {
	client.getRequestToken(function(error, token, tokenSecret) {
		res.redirect('https://twitter.com/oauth/authorize?oauth_token=' + token);
	});
});

app.get('/callback', function(req, res) {
	var token = req.query['oauth_token'];
	var verifier = req.query['oauth_verifier'];

	if (token && verifier) {
		client.getAccessToken(token, verifier, function(error, accessToken, accessTokenSecret) {
			if (!error) {
				client.getCredentials().setClient(accessToken, accessTokenSecret); // Set client access tokens

				client.get('http://twitter.com/account/verify_credentials.json', {}, function(error, response) {
					var profile = JSON.parse(response);
					res.send('<html><body><img src="' + profile.profile_image_url_https + '" /><br /><strong>' + profile.name + '</strong></body></html>');
					res.end();
				});
			}
		});
	}
});

app.listen(8000);
