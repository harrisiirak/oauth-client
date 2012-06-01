var util = require('util');
var crypto = require('crypto');
var URL = require('url');
var querystring = require('querystring');
var http = require('http');
var https = require('https');

var adapter = require('./adapter');

// OAuth header
function AuthorizationHeader(url, method, params, realm, fields, credentials) {
	this._realm = realm;
	this._url = url;
	this._method = method;
	this._credentials = credentials;

	// Set OAuth fields
	this._fields = fields || {};

	this._fields['oauth_timestamp'] = this._getTimestamp();
	this._fields['oauth_nonce'] = this._generateNonce();

	// Map signature values
	var signatureValues = [];
	this._mapDictionaryToArray(signatureValues, params);
	this._mapDictionaryToArray(signatureValues, this._fields);

	this._fields['oauth_signature'] = this._generateSignature(signatureValues);
}

AuthorizationHeader._nonceKey = 'abcdefghijklmnopqrstuvwxyz0123456789'; // Base string for unique nonce generation
AuthorizationHeader._nonceLength = 32;

AuthorizationHeader.Fields = {
	CONSUMER_KEY: 'oauth_consumer_key',
	CLIENT_TOKEN: 'oauth_token',
	VERSION: 'oauth_version',
	SIGNATURE: 'oauth_signature',
	SIGNATURE_METHOD: 'oauth_signature_method',
	NONCE: 'oauth_nonce',
	TIMESTMAP: 'oauth_timestamp',
	CALLBACK: 'oauth_callback'
};

AuthorizationHeader.prototype._encode = function(data) {
	if (typeof(data) === 'string') {
		return encodeURIComponent(data)
				.replace(/\!/g, '%21')
				.replace(/\'/g, '%27')
				.replace(/\(/g, '%28')
				.replace(/\)/g, '%29')
				.replace(/\*/g, '%2A');
	}

	return data;
};

AuthorizationHeader.prototype._decode = function(data) {
	if (typeof(data) === 'string') {
		return decodeURIComponent(data.replace(/\+/g, ' '));
	}

	return data;
};

AuthorizationHeader.prototype._mapDictionaryToArray = function(map, object) {
	for (var key in object) {
		if (typeof(object[key]) === 'object') {
			this._mapDictionaryToArray(map, object[key]);
		} else {
			map.push([key, object[key]]);
		}
	}

	return map;
};

AuthorizationHeader.prototype._generateSignature = function(parameters) {
	var signatureValue = '';
	var signatureKey = this._encode(this._credentials.consumer.secret) + '&' + (this._credentials.client.secret ? this._encode(this._credentials.client.secret) : '');

	if (this._fields[AuthorizationHeader.Fields.SIGNATURE_METHOD] === 'HMAC-SHA1') {
		// Encode parameters
		for (var c = parameters.length, i = 0; i < c; i++) {
			var parameter = parameters[i];
			parameter[0] = this._encode(parameter[0]);
			parameter[1] = this._encode(parameter[1]);
		}

		// Sort parameters
		parameters.sort(function(a, b) {
			if (a[0] === b[0]) { // Same keys (compare values)
				return a[1] > b[1] ? 1 : -1;
			} else { // Different keys (compare keys)
				return a[0] > b[0] ? 1 : -1;
			}
		});

		// Normalize URL
		var requestURL = URL.parse(this._url);
		if (requestURL.protocol === 'http:' || requestURL.protocol === 'https:') {
			this._url = requestURL.protocol + '//' + requestURL.hostname + (requestURL.port && requestURL.port !== '80' && requestURL.port !== '443' ? ':' + requestURL.port : '') + requestURL.path;
		} else {
			throw new Error('OAuth supports HTTP and HTTPS protocol only');
		}

		// Concat signature base string parts
		signatureValue += this._encode(this._method) + '&';
		signatureValue += this._encode(this._url) + '&';

		for (var c = parameters.length, i = 0; i < c; i++) {
			var parameter = parameters[i];
			signatureValue += this._encode(parameter[0] + '=' + parameter[1] + ((i + 1) !== c ? '&' : ''));
		}

		var hmac = crypto.createHmac('sha1', signatureKey).update(signatureValue);
		return hmac.digest('base64');
	} else { // Asume 'PLAINTEXT' method
		return signatureKey;
	}
};

AuthorizationHeader.prototype._generateNonce = function(data) {
	var nonce = '';
	var keyLength = AuthorizationHeader._nonceKey.length;

	for (var i = 0; i < AuthorizationHeader._nonceLength; i++) {
		nonce += AuthorizationHeader._nonceKey[Math.floor(Math.random() * keyLength)];
	}

	return nonce;
};

AuthorizationHeader.prototype._getTimestamp = function(data) {
	return Math.floor((new Date()).getTime() / 1000);
};

AuthorizationHeader.prototype.getHeader = function() {
	var header = 'OAuth ';

	for (var key in this._fields) {
		header += this._encode(key) + '="' + this._encode(this._fields[key]) + '",';
	}

	return header.substring(0, header.length - 1);
};

AuthorizationHeader.prototype.getURL = function() {
	// TODO: Implement
};

// Credentials
function AuthorizationCredentials(keys) {
	this._consumer = keys.consumer || { token: null, secret: null };
	this._client = keys.client || { token: null, secret: null };
}

AuthorizationCredentials.prototype.__defineGetter__('consumer', function() {
	return this._consumer;
});

AuthorizationCredentials.prototype.__defineGetter__('client', function() {
	return this._client;
});

// Adapter
function Adapter(options) {
	// TODO: Validate options
	this._options = options;
	this._options.version = '1.0';

	if (!this._options.callback) {
		this._options.callback = 'oob';
	}
}

util.inherits(Adapter, adapter.Adapter); // Inherit base adapter

Adapter.prototype._sendRequest = function(url, method, params, fields, credentials, callback) {
	var that = this;
	var requestHeaders = {};
	var queryParams = [];
	var requestProvider = null;
	var body = '';

	if (!fields) {
		fields = {};
	}

	var targetURL = URL.parse(url);
	var targetURLQueryParams = querystring.parse(targetURL.query) || {};
	//var targetURLBodyParams = body && body.length > 0 ? querystring.parse(body) : {};

	// Append query params
	for (var i in targetURLQueryParams) {
		var value = {};
		value[i] = targetURLQueryParams[i];
		queryParams.push(value);
	}

	// Set default OAuth fields
	fields[AuthorizationHeader.Fields.CONSUMER_KEY] = this._options.consumerKey;
	fields[AuthorizationHeader.Fields.SIGNATURE_METHOD] = this._options.signatureMethod;
	fields[AuthorizationHeader.Fields.VERSION] = this._options.version;

	var header = new AuthorizationHeader(url, method, queryParams, this._options.realm, fields, credentials);
	requestHeaders['Authorization'] = header.getHeader();
	requestHeaders['Host'] = targetURL.hostname;

	// Set content type when the request type is POST
	if (method === 'POST') {
		body = querystring.stringify(params);
		requestHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
		requestHeaders['Content-Length'] = body.length;
	}

	// Detect request protocol (HTTP or HTTPS)
	if (targetURL.protocol === 'https:') {
		requestProvider = https;
	} else {
		requestProvider = http;
	}

	var options = {
		host: targetURL.hostname,
		path: targetURL.path,
		method: method,
		headers: requestHeaders
	};

	if (targetURL.port !== undefined) {
		options.port = parseInt(targetURL.port);
	}

	var response = '';
	var req = requestProvider.request(options, function(res) {
		res.setEncoding('utf8');

		res.on('data', function(chunk) {
			response += chunk;
		});

		res.on('end', function() {
			if (res.statusCode >= 300 && res.statusCode <= 307) { // Redirect
				that._sendRequest(res.headers.location, method, params, fields, credentials, callback);
			} else if ((res.statusCode >= 200 && res.statusCode <= 206)) { // Normal response
				if (callback) {
					callback(null, response);
				}
			} else {
				callback(res.statusCode, response);
			}
		});
	});

	if (body.length > 0) {
		req.write(body);
	}

	req.end();
};

Adapter.prototype.getRequestToken = function(callback) {
	var credentials = new AuthorizationCredentials({
		consumer: {
			token: this._options.consumerKey,
			secret: this._options.consumerSecret
		}
	});

	var fields = {};
	fields[AuthorizationHeader.Fields.CALLBACK] = this._options.callback;

	// Acquire request token
	this._sendRequest(this._options.requestURL, 'POST', null, fields, credentials, function(error, data) {
		if (!error) {
			var params = querystring.parse(data);
			if (params['oauth_callback_confirmed'] === 'true') {
				if (callback) {
					callback(null, params['oauth_token'], params['oauth_token_secret']);
				}
			} else {
				if (callback) {
					callback(1, null, null); // FIXME: Better error code
				}
			}
		} else {
			if (callback) {
				callback(error, null, null);
			}
		}
	});
};

Adapter.prototype.getAccessToken = function() {

};

module.exports.Adapter = Adapter;
module.exports.AuthorizationHeader = AuthorizationHeader;
