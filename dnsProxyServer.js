var dns = require('native-dns'),
	stdio = require('stdio'),
	server = dns.createServer(),
	dnt = require('./dnsProxyCommon.js');

var argDescr = {
	'dnsname': {
		key: 'd',
		args: 1,
		description: 'The dns name of the dns server example: dns.example.com',
		required: true
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

//the system is built to support multiple targets the client can request a target based on the label in this struct
var Services = {
	s: {
		host: 'localhost',
		port: 22
	}
}

//packetID just used for debuging
packetID = 0;

//Sessions holds information about active sessions
var Sessions = new dnt.SessionsHolder();


function decode_edns_options(edns_options){
	var edns_subnet = false;

	//The edns data ussaly contains the subnet of the asker
	for(x in edns_options){
		if(edns_options[x].code == 8){
			family = edns_options[x].data.readUInt16BE();
			source = edns_options[x].data.readUInt8(2);
			scope = edns_options[x].data.readUInt8(3);
			adress = edns_options[x].data.slice(4)
			if(family == 1 || family == 2){//ipv4 or ipv6
				sep = '.';
				if(family == 2){
					sep = ':';
				}
				pos=0;
				adr = [];
				while(adress.length>pos){
					adr.push(adress.readUInt8(pos))
					pos++;
				}
				edns_subnet = adress.join(sep)+'/'+source;
			}
		}
	}
	return edns_subnet;

}

function onPacketFromClient(RecivedPacket, edns_subnet, question_name, asking_server_address, response, BytesLeft){
	var ret = {
		ResonseDelayed: false,
		BytesLeft: BytesLeft
	};
	var ThisPacketID = packetID;
	var Session = Sessions.get(RecivedPacket.sessionID);
	if(Session){
		if(edns_subnet){
			Session.clientLastKnownSubnet = edns_subnet;
		}
		Session.lastAskingServer = asking_server_address;
	}
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
					name: question_name,
					data: SubmitPacket.GetBinData(),
					ttl: 1
				}));
			} else {
				//console.log("Packet: " + ThisPacketID)
				var ResponseDelay = 0;
				if (RecivedPacket.data != 0) {
					PrintInfo("FrClient(" + RecivedPacket.commando + ")[" + RecivedPacket.offset + ":" + RecivedPacket.data.length + "] <- (client: " + RecivedPacket.sessionID + ")" + ThisPacketID)
					ResponseDelay = 5;
					Session.AddData(RecivedPacket.offset, RecivedPacket.data);
				}

				var RequestedOffset = RecivedPacket.recivedoffset;

				//We Wait {ResponseDelay}ms that way we can get the response We should not wait if there is allready a full message in the que, add that feature later...
				//from the server in the answer if there was no data from the client we use a ResponseDelay of zero
				ret.ResonseDelayed = true;
				setTimeout(function() {
					while (true) {
						var SubmitPacket = new dnt.ServerPacket();
						SubmitPacket.commando = 1;
						SubmitPacket.offset = RequestedOffset;
						SubmitPacket.recivedoffset = Session.NextByte;
						var TxtDatLeft = ret.BytesLeft - 13;
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
									name: question_name,
									data: SubmitPacket.GetBinData(),
									ttl: 1
								}));
							}
							break;
						} else {
							PrintInfo("ToClient(" + SubmitPacket.commando + ")[" + SubmitPacket.offset + ":" + SubmitPacket.data.length + "] -> (client: " + RecivedPacket.sessionID + ")" + ThisPacketID)
							var TxData = SubmitPacket.GetBinData();
							response.answer.push(dns.TXT({
								name: question_name,
								data: TxData,
								ttl: 1
							}));
							//console.error("BytesLeft", BytesLeft ,"TxData", TxData.length)
							ret.BytesLeft -= 13 + TxData.length;
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
				PrintInfo("Gave new SessionID to Client: " + SessionID.toString() + " source subnet: " + edns_subnet );
			} else {
				SubmitPacket.commando = 5;
				SubmitPacket.data = Buffer.from("3");
				PrintInfo("Client asked for a unknown service: " + Services[Service]);
			}
			response.answer.push(dns.TXT({
				name: question_name,
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
				name: question_name,
				data: SubmitPacket.GetBinData(),
				ttl: 1
			}));
			break;
	}
	return ret;
}

function onDnsRequest(request, input_response) {

	var response = input_response;
	var i;

	//packetID just used for debuging
	packetID += 1;

	var ResonseDelayed = false;

	//BytesLeft keeps track of the number of bytes used a UDP dns answerpacket may not exced 512 bytes
	var BytesLeft = 500; //512-12 The static part of a dns response is 12 bytes
	for (qt in response.question) {
		BytesLeft -= response.question[qt].name.length + 8;
	}


	//If we get edns info populate it in the edns_subnet variable
	var edns_subnet = decode_edns_options(request.edns_options);
	
	//Asking DNS server and subnet
	//console.log("asking server:", request.address.address, "source subnet:", adress);


	//Do this once per dns question There is a bug in this as the response will
	//be sent once per question. but the client only ever sends one question per message
	for (x in request.question) {

		//A question to one of the services that we support should look somthing
		//like: base32NUMdata base32data.dnsproxy.example.com
		var QuestionName = request.question[x].name;
		
		var ownDomain = QuestionName.substr(QuestionName.length - options.dnsname.length);
		var dataSubdomain = QuestionName.substr(0, QuestionName.length - options.dnsname.length);

		//Does the question end with our Special Domain Example: dnsproxy.example.com
		if (ownDomain == options.dnsname) {
			var RecivedPacket = new dnt.ClientPacket(dataSubdomain);

			//Was the message from the client decoded properly
			if (RecivedPacket) {
				ret = onPacketFromClient(RecivedPacket, edns_subnet, QuestionName, request.address.address, response, BytesLeft);
				ResonseDelayed = ret.ResonseDelayed;
				BytesLeft = ret.BytesLeft;
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
