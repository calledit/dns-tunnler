var Nibbler = require('./Nibbler.js').Nibbler,
	net = require('net');

module.exports.b32cbits = 5;
module.exports.base32 = new Nibbler({
	dataBits: 8,
	codeBits: module.exports.b32cbits,
	keyString: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',
	pad: '',
	arrayData: true
});

module.exports.Numbase32 = new Nibbler({
	dataBits: 20,
	codeBits: module.exports.b32cbits,
	keyString: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',
	pad: '',
	arrayData: true
});

module.exports.ServerPacket = function(BinData) {
	var self = this;
	self.crc = null;
	self.HeaderLen = 16;
	self.offset = null;
	self.recivedoffset = null;
	self.commando = null;
	self.data = Buffer.alloc(0);
	self.GetBinData = function() {
		var CDat = module.exports.Numbase32.encode([self.offset, self.recivedoffset, self.commando]) + module.exports.base32.encode(self.data);
		self.crc = 45;
		CDat = module.exports.Numbase32.encode([self.crc]) + CDat;
		return (CDat);

	}
	if (typeof(BinData) != 'undefined') {
		if (BinData.length < self.HeaderLen) {
			return (false); //Not a full header
		}
		var Headers = module.exports.Numbase32.decode(BinData.substr(0, self.HeaderLen));
		self.crc = Headers[0];
		self.offset = Headers[1];
		self.recivedoffset = Headers[2];
		self.commando = Headers[3];
		self.data = Buffer.from(module.exports.base32.decode(BinData.substr(self.HeaderLen)));
	}
}

module.exports.ClientPacket = function(BinData) {
	var self = this;
	self.crc = null;
	self.HeaderLen = 20;
	self.sessionID = null;
	self.offset = null;
	self.recivedoffset = null;
	self.commando = null;
	self.data = Buffer.alloc(0);
	self.GetBinData = function() {
		var CDat = module.exports.Numbase32.encode([self.sessionID, self.offset, self.recivedoffset, self.commando]) + module.exports.base32.encode(self.data);
		self.crc = 45;
		CDat = module.exports.Numbase32.encode([self.crc]) + CDat;
		ODat = [];
		while (CDat.length > 63) {
			ODat.push(CDat.substr(0, 63));
			CDat = CDat.substr(63)
		}
		if (CDat.length != 0) {
			ODat.push(CDat);
		}
		return (ODat.join('.'));
	}
	if (typeof(BinData) != 'undefined') {
		if (BinData.length < self.HeaderLen) {
			return (false); //Not a full header
		}
		BinData = BinData.split('.').join('');
		var Headers = module.exports.Numbase32.decode(BinData.substr(0, self.HeaderLen));
		self.crc = Headers[0];
		self.sessionID = Headers[1];
		self.offset = Headers[2];
		self.recivedoffset = Headers[3];
		self.commando = Headers[4];
		self.data = Buffer.from(module.exports.base32.decode(BinData.substr(self.HeaderLen)));
	}
}


module.exports.Session = function(host, port) {
	var self = this;

	self.DataPerRequest = 300;
	self.host = host;
	self.port = port;
	self.data = Buffer.alloc(0);
	self.unsentData = [];
	self.NextByte = 0;
	self.NextReadByte = 0;
	self.socket = net.connect(self.port, self.host, function() {});

	self.ReadBytes = [];

	self.GetLastReadByte = function() {
		var lastRead = 0;
		for (offset in self.ReadBytes) {
			if (offset <= lastRead) {
				lastRead = Math.max(parseInt(offset) + self.ReadBytes[offset], lastRead);
			}
		}
		return (lastRead);
	}

	self.IsThereUnReadBytes = function() {
		if (0 == self.data.length - self.GetLastReadByte()) {
			return (false);
		}
		return (true);
	}


	self.Read = function(length, offset) {
		var EndByte;
		if (typeof(offset) == 'undefined') {
			offset = self.NextReadByte;
		}
		EndByte = Math.min(self.data.length, offset + length);
		self.NextReadByte = Math.max(EndByte, self.NextReadByte);
		if (self.NextReadByte >= self.data.length) {
			self.socket.resume();
		}
		length = EndByte - offset;
		if (typeof(self.ReadBytes[offset]) == 'undefined') {
			self.ReadBytes[offset] = length;
		} else {
			self.ReadBytes[offset] = Math.max(length, self.ReadBytes[offset]);
		}
		return (self.data.slice(offset, EndByte));
	}

	self.AddData = function(offset, Data) {
		self.unsentData[offset] = Data;
		for (datOffset in self.unsentData) {
			if (self.NextByte == datOffset) {
				self.NextByte += self.unsentData[datOffset].length;
				self.socket.write(self.unsentData[datOffset]);
				delete self.unsentData[datOffset];
			}
		}

	}

	self.socket.on('error', function(err) {
		console.error("socket error")
	});
	self.socket.on('close', function() {
		console.error("socket closed")
	});
	self.socket.on('data', function(d) {
		self.data = Buffer.concat([self.data, d]);
		if (self.DataPerRequest + self.NextByte < self.data.length) {
			self.socket.pause();
		}
	});

}
module.exports.SessionsHolder = function() {
	var self = this;
	self.Sessions = [];
	self.get = function(SessionID) {
		if (typeof(self.Sessions[SessionID]) == 'undefined') {
			return (false); //No such session
		}
		return (self.Sessions[SessionID]);
	}
	self.add = function(host, port) {
		var SessionID = self.Sessions.length;
		self.Sessions[SessionID] = new module.exports.Session(host, port);
		return (SessionID);
	}
}
