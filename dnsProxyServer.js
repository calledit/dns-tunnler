var dns = require('native-dns'),
	stdio = require('stdio'),
	server = dns.createServer(),
	dnt = require('./dnsProxyCommon.js');

var argDescr = {
	'dnsname': {
		key: 'd',
		args: 1,
		description: 'The dns name of the dns server example: dns.example.com',
		mandatory: true
	},
	'listenip': {
		key: 'l',
		args: 1,
		default: '0.0.0.0',
		description: 'The ip number to start listening to default is 0.0.0.0'
	},
	'port': {
		key: 'p',
		args: 1,
		default: 53,
		pharse: parseInt,
		description: 'The port to listen to default i 53'
	},
	'timeout': {
		key: 't',
		args: 1,
		default: 300,
		pharse: function(timeout) {
			return (parseInt(timeout) * 1000)
		},
		description: 'Nr of seconds of inacvivity untill the session is considerd dead default is 300'
	},
	'verbose': {
		key: 'v',
		description: 'Print more information to stderr'
	}
};
var options = stdio.getopt(argDescr);

//Set Default Argument Values and pharse them
for (ArgName in argDescr) {
	if (!options[ArgName] && argDescr[ArgName].default) {
		options[ArgName] = argDescr[ArgName].default;
	}

	if (argDescr[ArgName].pharse && options[ArgName]) {
		options[ArgName] = argDescr[ArgName].pharse(options[ArgName]);
	}
}

var Services = {
	s: {
		host: 'localhost',
		port: 1337
	}
}

packetID = 0;

var Sessions = new dnt.SessionsHolder();

function onDnsRequest(request, input_response) {
	var response = input_response;
	var i;

	packetID += 1;

	var ThisPacketID = packetID;

	var ResonseDelayed = false;

	//A UDP dns answerpacket may not exced 512 bytes
	var BytesLeft = 500; //512-12 The static part of a dns response is 12 bytes
	for (qt in response.question) {
		BytesLeft -= response.question[qt].name.length + 8;
	}
	//Do this once per dns question There is a bug in this as the response will
	//be sent once per question.
	for (x in request.question) {

		//A question to one of the services that we support should look somthing
		//like: base32NUMdata base32data.dnsproxy.example.com
		var QuestionName = request.question[x].name;

		//Does the question end with our Special Domain Example: dnsproxy.example.com
		if (QuestionName.substr(QuestionName.length - options.dnsname.length) == options.dnsname) {
			var RecivedPacket = new dnt.ClientPacket(QuestionName.substr(0, QuestionName.length - options.dnsname.length));

			if (RecivedPacket) {
				var Session = Sessions.get(RecivedPacket.sessionID);
				//PrintInfo("SessionID: "+RecivedPacket.sessionID+" RcOf: "+RecivedPacket.recivedoffset+" Of: "+RecivedPacket.offset+" DatLen: "+RecivedPacket.data.length);
				switch (RecivedPacket.commando) {
					case 1: //Data recive & recive
					case 3: //Data retrive
						if (!Session) {
							PrintInfo("Recived unknown SessionID: " + RecivedPacket.sessionID);
							var SubmitPacket = new dnt.ServerPacket();
							SubmitPacket.commando = 5;
							SubmitPacket.data = Buffer.from("1");
							response.answer.push(dns.TXT({
								name: request.question[x].name,
								data: SubmitPacket.GetBinData(),
								ttl: 1
							}));
						} else {
							console.log("Packet: " + ThisPacketID)
							var ResponseDelay = 0;
							if (RecivedPacket.data != 0) {
								PrintInfo("FrClient(" + RecivedPacket.commando + ")[" + RecivedPacket.offset + ":" + RecivedPacket.data.length + "] <- (client: " + RecivedPacket.sessionID + ")" + ThisPacketID)
								ResponseDelay = 50;
								Session.AddData(RecivedPacket.offset, RecivedPacket.data);
							}

							var RequestedOffset = RecivedPacket.recivedoffset;

							//We Wait {ResponseDelay}ms that way we can get the response
							//from the server in the answer if there was no data from the client we use a ResponseDelay of zero
							ResonseDelayed = true;
							setTimeout(function() {
								while (true) {
									var SubmitPacket = new dnt.ServerPacket();
									SubmitPacket.commando = 1;
									SubmitPacket.offset = RequestedOffset;
									SubmitPacket.recivedoffset = Session.NextByte;
									var TxtDatLeft = BytesLeft - 13;
									var MaxDatLeft = Math.min(TxtDatLeft, 255);
									var UsableTxDatBytesLeft = MaxDatLeft - SubmitPacket.HeaderLen;
									var MaxData2Client_Len = Math.floor(UsableTxDatBytesLeft * (dnt.b32cbits / 8)); ///A Anser may maximumly be 254 bytes
									if (MaxData2Client_Len > 0) {
										SubmitPacket.data = Session.Read(MaxData2Client_Len, SubmitPacket.offset);

										if (Session.IsThereUnReadBytes()) {
											SubmitPacket.commando = 4;
										}
										//console.error("Read bytes: ", Session.GetLastReadByte()," Client Recived: ", RecivedPacket.recivedoffset);
										RequestedOffset += SubmitPacket.data.length;
									}

									if (SubmitPacket.data.length == 0) {
										if (response.answer.length == 0) {
											SubmitPacket.commando = 3;
											response.answer.push(dns.TXT({
												name: request.question[x].name,
												data: SubmitPacket.GetBinData(),
												ttl: 1
											}));
										}
										break;
									} else {
										PrintInfo("ToClient(" + SubmitPacket.commando + ")[" + SubmitPacket.offset + ":" + SubmitPacket.data.length + "] -> (client: " + RecivedPacket.sessionID + ")" + ThisPacketID)
										var TxData = SubmitPacket.GetBinData();
										response.answer.push(dns.TXT({
											name: request.question[x].name,
											data: TxData,
											ttl: 1
										}));
										//console.error("BytesLeft", BytesLeft ,"TxData", TxData.length)
										BytesLeft -= 13 + TxData.length;
									}
								}
								response.send();
							}, ResponseDelay);
						}
						break;
					case 2: //New Session
						var Service = RecivedPacket.data.toString();
						var SubmitPacket = new dnt.ServerPacket();
						if (typeof(Services[Service]) != 'undefined') {
							var SessionID = Sessions.add(Services[Service].host, Services[Service].port);
							SubmitPacket.commando = 2;
							SubmitPacket.data = Buffer.from(SessionID.toString());
							PrintInfo("Gave new SessionID to Client: " + SessionID.toString());
						} else {
							SubmitPacket.commando = 5;
							SubmitPacket.data = Buffer.from("3");
							PrintInfo("Client asked for a unknown service: " + Services[Service]);
						}
						response.answer.push(dns.TXT({
							name: request.question[x].name,
							data: SubmitPacket.GetBinData(),
							ttl: 1
						}));
						break;
					case 5: //Error
						PrintInfo("Client reported error: " + RecivedPacket.data.toString());
						break;
					default:
						PrintInfo("Unknown comamndo recived from client.");
						var SubmitPacket = new dnt.ServerPacket();
						SubmitPacket.commando = 5;
						SubmitPacket.data = Buffer.from("2");

						response.answer.push(dns.TXT({
							name: request.question[x].name,
							data: SubmitPacket.GetBinData(),
							ttl: 1
						}));
						break;
				}

			} else {
				PrintInfo("The question does not have the correct number of heders");
			}
		} else {
			PrintInfo("Question not for us:" + request.question[x].name);
		}
	}
	if (!ResonseDelayed) {
		response.send();
	}
};

function PrintInfo(VerbTxT) {
	if (options.verbose) {
		var now = new Date();
		console.error(now.getHours() + ':' + now.getMinutes() + ':' + now.getSeconds() + ' ' + VerbTxT);
	}
}

var onError = function(err, buff, req, res) {
	console.error('DNS ERROR:', err);
};

var onListening = function() {
	//console.log('server listening on', this.address());
	//this.close();
};

var onSocketError = function(err, socket) {
	console.log(err);
};

var onClose = function() {
	PrintInfo('server closed', this.address());
};

server.on('request', onDnsRequest);
server.on('error', onError);
server.on('listening', onListening);
server.on('socketError', onSocketError);
server.on('close', onClose);

server.serve(options.port, options.listenip);
