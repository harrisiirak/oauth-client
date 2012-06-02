function Adapter() {

}

Adapter.prototype.getCredentials = function() {
	throw Error('Unimplemented method');
};

Adapter.prototype.setCredentials = function() {
	throw Error('Unimplemented method');
};

Adapter.prototype.getRequestToken = function() {
	throw Error('Unimplemented method');
};

Adapter.prototype.getAccessToken = function() {
	throw Error('Unimplemented method');
};

Adapter.prototype.get = function() {
	throw Error('Unimplemented method');
};

Adapter.prototype.post = function() {
	throw Error('Unimplemented method');
};

module.exports.Adapter = Adapter;
