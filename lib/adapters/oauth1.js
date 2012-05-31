var util = require('util');
var crypto = require('crypto');
var URL = require('url');
var querystring = require('querystring');

var adapter = require('./adapter');

// OAuth header
function AuthenticationHeader(consumerKey, consumerSecret, signatureMethod, version, realm, url, params, method, fields) {
	this._fields = {} || fields;
	this._fields['oauth_consumer_key'] = consumerKey;
	this._fields['oauth_signature_method'] = signatureMethod;
	this._fields['oauth_timestamp'] = this._getTimestamp();
	this._fields['oauth_nonce'] = this._generateNonce();

	this._consumerKey = consumerKey;
	this._consumerSecret = consumerSecret;
	this._signatureMethod = signatureMethod;
	this._version = version;
	this._realm = realm;
	this._url = url;
	this._method = method;

	// Map signature values
	var signatureValues = [];
	this._mapDictionaryToArray(signatureValues, params);
	this._mapDictionaryToArray(signatureValues, this._fields);

	console.log(signatureValues);
	/*
	for (var c = params.length, i = 0; i < c; i++) {
		this._signatureValues.push(params[i]);
	}
	*/
}

AuthenticationHeader._nonceKey = 'abcdefghijklmnopqrstuvwxyz0123456789'; // Base string for unique nonce generation
AuthenticationHeader._nonceLength = 64;

AuthenticationHeader.prototype._encode = function(data) {
	if ((data instanceof String)) {
		return encodeURIComponent(data)
				.replace(/\!/g, '%21')
				.replace(/\'/g, '%27')
				.replace(/\(/g, '%28')
				.replace(/\)/g, '%29')
				.replace(/\*/g, '%2A');
	}

	return '';
};

AuthenticationHeader.prototype._decode = function(data) {
	if ((data instanceof String)) {
		return decodeURIComponent(data.replace(/\+/g, ' '));
	}

	return '';
};

AuthenticationHeader.prototype._mapDictionaryToArray = function(map, object) {
	for (var key in object) {
		if (typeof(object[key]) === 'object') {
			this._mapDictionaryToArray(map, object[key]);
		} else {
			map.push([key, object[key]]);
		}
	}

	return map;
};

AuthenticationHeader.prototype._generateNonce = function(data) {
	var nonce = '';
	var keyLength = AuthenticationHeader._nonceKey.length;

	for (var i = 0; i < AuthenticationHeader._nonceLength; i++) {
		nonce += AuthenticationHeader._nonceKey[Math.floor(Math.random() * keyLength)];
	}

	return nonce;
};

AuthenticationHeader.prototype._getTimestamp = function(data) {
	return Math.floor((new Date()).getTime() / 1000);
};

AuthenticationHeader.prototype.getHeader = function() {
	var header = 'Authorization: OAuth realm="' + realm + '",';
};

AuthenticationHeader.prototype.getURL = function() {

};

// Adapter
function Adapter(options) {
	// TODO: Validate options
	this._options = options;
	this._options.version = '1.0A';
}

util.inherits(Adapter, adapter.Adapter); // Inherit base adapter

Adapter.prototype._sendRequest = function(url, method, body, authenticationHeader) {
	url += '?b5=%3D%253D&a3=a&c%40=&a2=r%20b';
	body = 'c2&a3=2+q';

	var targetURL = URL.parse(url);
	var queryParams = [];
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

	var header = new AuthenticationHeader(this._options.consumerKey,
										  this._options.consumerSecret,
										  this._options.signatureMethod,
										  this._options.version,
										  this._options.realm,
										  url,
										  queryParams,
										  method,
										  {});
};

Adapter.prototype.getRequestToken = function(callback) {
	this._sendRequest(this._options.requestURL, 'GET', null);
};

Adapter.prototype.getAccessToken = function() {

};

module.exports.Adapter = Adapter;
module.exports.AuthenticationHeader = AuthenticationHeader;
