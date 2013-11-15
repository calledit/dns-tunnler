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
        pharse: function(timeout){return(parseInt(timeout)*1000)},
		description: 'Nr of seconds of inacvivity untill the session is considerd dead default is 300'
	},
	'verbose': {
		key: 'v',
		description: 'Print more information to stderr'
	}
};
var options = stdio.getopt(argDescr);

//Set Default Argument Values and pharse them
for(ArgName in argDescr){
    if(!options[ArgName] && argDescr[ArgName].default){
        options[ArgName] = argDescr[ArgName].default;
    }
    
    if(argDescr[ArgName].pharse && options[ArgName]){
        options[ArgName] = argDescr[ArgName].pharse(options[ArgName]);
    }
}

var Services = {
        s: {
                host: 'localhost',
                port: 1337
        }
}


var Sessions = new dnt.SessionsHolder();

function onDnsRequest(request, response) {
	var i;

	//PrintInfo("# Got query from: " + request._socket._remote.address + " with: " + request.question.length + " question(s)")

	//A UDP dns answerpacket may not exced 512 bytes
	var RemaningChars = 500; //512-12 The static part of a dns response is 12 bytes
	for (qt in response.question) {
		RemaningChars -= response.question[qt].name.length + 8;
	}
	//Do this once per dns question
	for (x in request.question) {
        
		//A question to one of the services that we support should look somthing
		//like: base32NUMdata base32data.dnsproxy.example.com
		var QuestionName = request.question[x].name;

		//Does the question end with our Special Domain Example: dnsproxy.example.com
		if (QuestionName.substr(QuestionName.length - options.dnsname.length) == options.dnsname) {
            var RecivedPacket = new dnt.ClientPacket(QuestionName.substr(0, QuestionName.length - options.dnsname.length));
            
            if(RecivedPacket){
                var SubmitPacket = new dnt.ServerPacket();
                var Session = Sessions.get(RecivedPacket.sessionID);
                switch(RecivedPacket.commando){
                    case 1://Data recive & recive
                    case 3://Data retrive
                        if(!Session){
			                PrintInfo("Recived unknown SessionID: "+RecivedPacket.sessionID);
                            SubmitPacket.commando = 5;
                            SubmitPacket.data = new Buffer("1");
                        }else{
                            SubmitPacket.commando = 1;
                            if(RecivedPacket.data != 0){
                                PrintInfo("Session: "+RecivedPacket.sessionID+": <- "+RecivedPacket.data.length)
                                Session.AddData(RecivedPacket.offset, RecivedPacket.data);
                            }
                            SubmitPacket.offset = Session.NextReadByte;
                            SubmitPacket.recivedoffset = Session.NextByte;
                            SubmitPacket.data = Session.Read(100, RecivedPacket.recivedoffset);
                            if(SubmitPacket.data.length == 0){
                                SubmitPacket.commando = 3;
                            }else{
                                PrintInfo("Session: "+RecivedPacket.sessionID+": -> "+SubmitPacket.data.length+": "+RecivedPacket.recivedoffset)
                            }
                        }
                        break;
                    case 2://New Session
                        var Service = RecivedPacket.data.toString();
                        if(typeof(Services[Service]) != 'undefined'){
                            var SessionID = Sessions.add(Services[Service].host, Services[Service].port);
                            SubmitPacket.commando = 2;
                            SubmitPacket.data = new Buffer(SessionID.toString());
			                PrintInfo("Gave new SessionID to Client: " + SessionID.toString());
                        }else{
                            SubmitPacket.commando = 5;
                            SubmitPacket.data = new Buffer("3");
			                PrintInfo("Client asked for a unknown service: " + Services[Service]);
                        }
                        break;
                    case 5://Error
			            PrintInfo("Client reported error: "+RecivedPacket.data.toString());
                        break;
                    default:
			            PrintInfo("Unknown comamndo recived from client.");
                        SubmitPacket.commando = 5;
                        SubmitPacket.data = new Buffer("2");
                        break;
                }

				response.answer.push(dns.TXT({
					name: request.question[x].name,
					data: SubmitPacket.GetBinData(),
					ttl: 1
				}));
                
            }else{
			    PrintInfo("The question does not have the correct number of heders");
            }
		} else {
			PrintInfo("Question not for us:"+ request.question[x].name);
			/*
  		response.answer.push(dns.TXT({
    		name: "Unknown.main.domain",
    		data: '127.0.0.1',
    		ttl: 1,
  		}));
  		*/
		}
	}

	//To reduce Over head Causes errors in most dns implementations
	//response.question = [ { name: ProxyOwner, type: 16, class: 1 } ];
	//console.error('Submit Response');
	response.send();
	//PrintInfo("__________________________________________")
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


function CreateNewSession(cPoolId, ServiceID) {
	//we can send about 300 bytes of pure data per Question
	ConnectionPool[cPoolId] = {
		'Data2ClientPerQuestion': 300,
		'TotalSentToClient': 0,
		'TotalRecivedFromClient': 0,
		'data': new Buffer(0),
		'socket': null,
		'updata': [],
		'ServiceID': ServiceID,
		'DowndataID': 0,
		'LastUpdataID': 4,
		'PrevAnswers': [],
        'timeout':null
	};

    ConnectionPool[cPoolId].timout = setTimeout(ConnectionPool[cPoolId].socket.close, options.timeout);


}

function HandleClientData(cPoolId, DataDomains, PacketData) {
	//A subdomain can only be 63 bytes long so the data is splited in to several subdomains
	var Bs32Data = '';
	for (var i = 0; i < DataDomains.length - 2; i++) {
		Bs32Data += DataDomains[i];
	}

	//var PacketData = Numbase32.decode(DataDomains[DataDomains.length-3]);
	var UpdataID = PacketData[2];

	if (typeof(ConnectionPool[cPoolId].updata[UpdataID]) == 'undefined') {
		ConnectionPool[cPoolId].updata[UpdataID] = new Buffer(base32.decode(Bs32Data));
		PrintInfo('Recived data width upid: ' + UpdataID);
		if (ConnectionPool[cPoolId].LastUpdataID + 1 == UpdataID) {
			while (typeof(ConnectionPool[cPoolId].updata[ConnectionPool[cPoolId].LastUpdataID + 1]) != 'undefined') {
				ConnectionPool[cPoolId].socket.write(
					ConnectionPool[cPoolId].updata[ConnectionPool[cPoolId].LastUpdataID + 1]
				);
				delete ConnectionPool[cPoolId].updata[ConnectionPool[cPoolId].LastUpdataID + 1];
				ConnectionPool[cPoolId].LastUpdataID += 1;
			}
		}
	} else {
		PrintInfo('	Got data width upid: ' + UpdataID + ' More than one time');
	}
}

function HandleServerData(cPoolId, responseQuestion, Answers, RemaningChars) {

	var TotalBytes = 0;


	var CharsPerAnswer = 254; //An answer can only hold 254 Chars
	//While we have Data in the buffers and the dns answer is not to long
	while (ConnectionPool[cPoolId].data.length != 0 && RemaningChars > 0) {


		var UseDownID = ConnectionPool[cPoolId].DowndataID;
		var DatArrs = [];


		//Numbase32.encode([Math.round(Math.random()*100000)]);
		var NameToUse = responseQuestion.name;
		var MetaToClient = cPoolId + "." + UseDownID + '.' + ConnectionPool[cPoolId].data.length + ':';

		var CharsInAnswer = Math.min(CharsPerAnswer, RemaningChars) - (13 + MetaToClient.length); //There is 13 static bytes in a txt record

		if (0 < CharsInAnswer) {
			var MaxBytesinAnswer = Math.floor(CharsInAnswer * (6 / 8));
			var BytesinAnswer = Math.min(MaxBytesinAnswer, ConnectionPool[cPoolId].data.length);
			TotalBytes += BytesinAnswer;

			DatArrs.push(MetaToClient + ConnectionPool[cPoolId].data.slice(0, BytesinAnswer).toString('base64'));
			ConnectionPool[cPoolId].data = ConnectionPool[cPoolId].data.slice(BytesinAnswer);
			ConnectionPool[cPoolId].DowndataID++;
			if (ConnectionPool[cPoolId].Data2ClientPerQuestion > ConnectionPool[cPoolId].data.length) {
				ConnectionPool[cPoolId].socket.resume();
			}


			//The loop is unnececary
			for (DPA in DatArrs) {
				//console.error('Answer',DatArrs[DPA]);
				RemaningChars -= DatArrs[DPA].length + 13; //A answer costs some static bytes
				Answers.push(dns.TXT({
					name: NameToUse,
					data: DatArrs[DPA],
					ttl: 1
				}));
			}
		} else {
			break;
		}
	}
	if (TotalBytes != 0) {
		PrintInfo("	Sent " + TotalBytes + " bytes to Client, " + ConnectionPool[cPoolId].data.length + " bytes left in buffer");
		ConnectionPool[cPoolId].TotalSentToClient += TotalBytes;
	}
	return (RemaningChars);
}

function HandleQuestionToUs(DataDomains, responseQuestion, requestQuestion, Answers, RemaningChars) {
	//is the question intended for one of the services we support
	if (DataDomains.length > 1) {
		var ServiceID = DataDomains[DataDomains.length - 1];
		if (typeof(Services[ServiceID]) != 'undefined') {

			//which Socket we wan't 
			var PacketData = Numbase32.decode(DataDomains[DataDomains.length - 2]);
			if (PacketData.length < 3) {
				PrintInfo('	Data recived from client is corrupt. atleast cPoolId, LastRecivedID, DnsUpId and requestcounter needs to be set in a request');
                ReportError(Answers, requestQuestion.name, "PacketData corupt");
			} else {
				var cPoolId = PacketData[0];
				var LastRecivedID = PacketData[1];
				var RequestCounter = PacketData[3];
				PrintInfo('	question regarding session: ' + cPoolId);


				if (typeof(ConnectionPool[cPoolId]) == 'undefined') {
					//If The ConnectionPoolID was unknown we create a connection with that id
					if (RequestCounter == 0) {
						PrintInfo("	this is a new session to service " + ServiceID + " establishing new connection to service server");
						CreateNewSession(cPoolId, ServiceID);

					} else {
						PrintInfo("Got a new cPoolId where the request counter was not 0. Probably a replay of dead session");
                        ReportError(Answers, requestQuestion.name, "SessionNotKnown");
					}
				} else {
					//The Connection Already exists in the connection pool
                    clearTimeout(ConnectionPool[cPoolId].timout);
                    ConnectionPool[cPoolId].timout = setTimeout(ConnectionPool[cPoolId].socket.close, options.timeout);

                    //Remove answers that we are sure the client has recived
					for (reqid in ConnectionPool[cPoolId].PrevAnswers) {
						if (ConnectionPool[cPoolId].PrevAnswers[reqid].LastDownDataID <= LastRecivedID) {
							delete ConnectionPool[cPoolId].PrevAnswers[reqid];
						}
					}

                    //Add answers that the client missed to the submit que
					if (typeof(ConnectionPool[cPoolId].PrevAnswers[RequestCounter]) != 'undefined') {
						for (ansid in ConnectionPool[cPoolId].PrevAnswers[RequestCounter].Ans) {
							Answers.push(ConnectionPool[cPoolId].PrevAnswers[RequestCounter].Ans[ansid]);
						}
					} else {
						/*
                        ############################################################
                        Handle upData from The client
                        ############################################################
                        */
						if (DataDomains.length > 2 && typeof(PacketData[2]) != 'undefined') {
							//When there is updata there is more than 2 extra subdomains
							HandleClientData(cPoolId, DataDomains, PacketData);
						}

						/*
                        ############################################################
                        Submit Data to The client
                        ############################################################
                        */

						RemaningChars = HandleServerData(cPoolId, responseQuestion, Answers, RemaningChars);
						ConnectionPool[cPoolId].PrevAnswers[RequestCounter] = {
							'LastDownDataID': ConnectionPool[cPoolId].DowndataID,
							'Ans': Answers
						};
					}
				}
			}
		} else {
			PrintInfo("Client ask for a service that we dont support:", requestQuestion.name);
            //ReportError(Answers, requestQuestion.name, "ServiceNotSupported");
            
			/*
  			response.answer.push(dns.TXT({
    			name: "Unknown.service.alias",
    			data: '127.0.0.2',
    			ttl: 1,
  			}));*/
		}
	} else {
		PrintInfo("Question does not apper to be corectly formated:", requestQuestion.name);
		/*
  		response.answer.push(dns.TXT({
    		name: "to.few.subdomain.entrys",
    		data: '127.0.0.2',
    		ttl: 1,
  		}));*/
	}
	return (RemaningChars);
}


function ReportError(Answers, Name, Error){
    Answers.push(dns.TXT({
        name: Name,
        data: Error,
        ttl: 1
    }));
}
