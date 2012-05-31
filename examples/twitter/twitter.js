var express = require('express');
var oauth = require('../../lib').Client;

var app = express.createServer();

app.get('/', function(require, res) {

});

var client = oauth.createClient(oauth.Version.OAUTH1, {
	consumerKey: 'fNRoVPyBJpgrtrXrIx6Og',
	consumerSecret: 'yd3O5lvux87WHVidnNg2SE7yk8pecWZFZaaspYeSZQ',
	requestURL: 'https://twitter.com/oauth/request_token',
	accessURL: 'https://twitter.com/oauth/access_token',
	signatureMethod: oauth.Signature.HMACSHA1,
	callback: 'http://127.0.0.1:8000/callback',
	realm: 'Node.js OAuth Client',
	headers: {

	}
});

//console.log(client);

app.listen(8000);
