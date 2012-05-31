var util = require('util');
var adapter = require('./adapter');

// OAuth header
function AuthenticationHeader(consumerKey, consumerSecret, signatureMethod, version, realm, url, method, fields) {
	this._fields = {} || fields;
	this._consumerKey = consumerKey;
	this._consumerSecret = consumerSecret;
	this._signatureMethod = signatureMethod;
	this._version = version;
	this._realm = realm;
	this._url = url;
	this._method = method;
}

AuthenticationHeader.prototype._encode = function(data) {

};

AuthenticationHeader.prototype._decode = function(data) {

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

	return this;
}

util.inherits(Adapter, adapter.Adapter); // Inherit base adapter

Adapter.prototype._sendRequest = function(url, method, authenticationHeader) {

};

Adapter.prototype.getRequestToken = function(callback) {
	this._sendRequest(this._options.requestURL, 'GET', new AuthenticationHeader(this._options.consumerKey,
																				this._options.consumerSecret,
																				this._options.signatureMethod,
																				this._options.version,
																				this._options.realm,
																				this._options.requestURL,
																				'GET',
																				{

																				}));
};

Adapter.prototype.getAccessToken = function() {

};

module.exports.Adapter = Adapter;
module.exports.Header = Header;
