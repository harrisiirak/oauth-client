var util = require('util');
var crypto = require('crypto');
var URL = require('url');
var querystring = require('querystring');
var http = require('http');
var https = require('https');

var adapter = require('./adapter');

// OAuth header
function AuthorizationHeader(consumerKey, consumerSecret, signatureMethod, version, realm, url, params, method, fields) {
	this._consumerKey = consumerKey;
	this._consumerSecret = this._encode(consumerSecret);
	this._signatureMethod = signatureMethod;
	this._version = version;
	this._realm = realm;
	this._url = url;
	this._method = method;

	// Set OAuth fields
	this._fields = {} || fields;
	this._fields['oauth_consumer_key'] = consumerKey;
	this._fields['oauth_version'] = version;
	this._fields['oauth_signature_method'] = signatureMethod;
	this._fields['oauth_timestamp'] = this._getTimestamp();
	this._fields['oauth_nonce'] = this._generateNonce();

	// Map signature values
	var signatureValues = [];
	this._mapDictionaryToArray(signatureValues, params);
	this._mapDictionaryToArray(signatureValues, this._fields);

	this._fields['oauth_signature'] = this._generateSignature(signatureValues);
}

AuthorizationHeader._nonceKey = 'abcdefghijklmnopqrstuvwxyz0123456789'; // Base string for unique nonce generation
AuthorizationHeader._nonceLength = 64;

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
	var signatureKey = this._consumerSecret + '&' + (this._fields['oauth_token'] ? this._fields['oauth_token'] : '');

	if (this._signatureMethod === 'HMAC-SHA1') {
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
			this._url = requestURL.protocol + '//' + requestURL.hostname + (requestURL.port !== '80' && requestURL.port !== '443' ? ':' + requestURL.port : '') + requestURL.path;
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
		header += ',' + key + '=' + this._fields[key];
	}

	return header;
};

AuthorizationHeader.prototype.getURL = function() {

};

// Adapter
function Adapter(options) {
	// TODO: Validate options
	this._options = options;
	this._options.version = '1.0A';
}

util.inherits(Adapter, adapter.Adapter); // Inherit base adapter

Adapter.prototype._sendRequest = function(url, method, body, authorizationHeader) {
	url += '?b5=%3D%253D&a3=a&c%40=&a2=r%20b';
	body = 'c2&a3=2+q';

	var requestHeaders = {};
	var queryParams = [];
	var requestProvider = null;

	var targetURL = URL.parse(url);
	var targetURLQueryParams = querystring.parse(targetURL.query) || {};
	var targetURLBodyParams = body && body.length > 0 ? querystring.parse(body) : {};

	// Append query params
	for (var i in targetURLQueryParams) {
		var value = {};
		value[i] = targetURLQueryParams[i];
		queryParams.push(value);
	}

	for (var i in targetURLBodyParams) {
		var value = {};
		value[i] = targetURLBodyParams[i];
		queryParams.push(value);
	}

	var header = new AuthorizationHeader(this._options.consumerKey,
										  this._options.consumerSecret,
										  this._options.signatureMethod,
										  this._options.version,
										  this._options.realm,
										  url,
										  queryParams,
										  method,
										  {});

	// Set content type when the request type is POST
	if (method === 'POST' && body) {
		requestHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
	}
};

Adapter.prototype.getRequestToken = function(callback) {
	this._sendRequest(this._options.requestURL, 'GET', null);
};

Adapter.prototype.getAccessToken = function() {

};

module.exports.Adapter = Adapter;
module.exports.AuthorizationHeader = AuthorizationHeader;
