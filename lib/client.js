
function Client() {

};

// Define adapter versions
Client.Version = {
	OAUTH1: 1,
	OAUTH2: 2
};

Client.Signature = {
	HMACSHA1: 'HMAC-SHA1',
	PLAINTEXT: 'PLAINTEXT'
};

Client.createClient = function(version, options) {
	switch (version) {
		case Client.Version.OAUTH1:
			return new (require('./adapters/oauth1').Adapter)(options);
			break;

		case Client.Version.OAUTH2:
			break;
	}

	throw Error('Invalid client version');
};

module.exports.Client = Client;
