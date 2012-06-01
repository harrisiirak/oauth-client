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
		signatureValue += this._encode(this._url);

		for (var c = parameters.length, i = 0; i < c; i++) {
			var parameter = parameters[i];
			signatureValue += '&' + parameter[0] + '=' + parameter[1];
		}

		console.log(signatureKey);
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
	var header = 'OAuth realm="' + this._realm + '"';

	for (var key in this._fields) {
		header += ',' + this._encode(key) + '=' + this._encode(this._fields[key]);
	}

	return header;
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

Adapter.prototype._sendRequest = function(url, method, params, credentials) {
	var requestHeaders = {};
	var queryParams = [];
	var requestProvider = null;
	var body = '';

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
	var fields = {};
	fields[AuthorizationHeader.Fields.CONSUMER_KEY] = this._options.consumerKey;
	fields[AuthorizationHeader.Fields.SIGNATURE_METHOD] = this._options.signatureMethod;
	fields[AuthorizationHeader.Fields.VERSION] = this._options.version;
	fields[AuthorizationHeader.Fields.CALLBACK] = this._options.callback;

	var header = new AuthorizationHeader(url, method, queryParams, this._options.realm, fields, credentials);
	requestHeaders['Authorization'] = header.getHeader();

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

	var options = targetURL;
	options.method = method;
	options.headers = requestHeaders;

	//console.log(options);

	var req = requestProvider.request(options, function(res) {
	  console.log('STATUS: ' + res.statusCode);
	  //console.log('HEADERS: ' + JSON.stringify(res.headers));
	  res.setEncoding('utf8');
	  res.on('data', function (chunk) {
		console.log('BODY: ' + chunk);
	  });
	});

	req.on('error', function(e) {
	  console.log('problem with request: ' + e.message);
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

	this._sendRequest(this._options.requestURL, 'POST', null, credentials);
};

Adapter.prototype.getAccessToken = function() {

};

module.exports.Adapter = Adapter;
module.exports.AuthorizationHeader = AuthorizationHeader;
