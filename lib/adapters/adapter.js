function Adapter() {

}

Adapter.prototype.getRequestToken = function() {
	throw Error('Unimplemented method');
};

Adapter.prototype.getAccessToken = function() {
	throw Error('Unimplemented method');
};

module.exports.Adapter = Adapter;
