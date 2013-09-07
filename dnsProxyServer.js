var dns = require('native-dns'),
  stdio = require('stdio'),
  server = dns.createServer(),
  tcpserver,
  net = require('net'),
  Nibbler = require('./Nibbler.js').Nibbler;

var options = stdio.getopt({
    'dnsname': {key: 'd', args: 1, description: 'The dns name of the dns server example: dns.example.com', mandatory: true},
    'listenip': {key: 'l',args:1, description: 'The ip number to start listening to default is 0.0.0.0'},
    'port': {key: 'p', args: 1, description: 'The port to listen to default i 53'},
    'verbose': {key: 'v', description: 'Print more information to stderr'}
});

if(!options.listenip){
    options.listenip = '0.0.0.0';
}
if(!options.port){
    options.port = 53;
}


var b32cbits = 5;
var base32 = new Nibbler({
    dataBits: 8,
    codeBits: b32cbits,
    keyString: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',
    pad: '',
    arrayData: true
});


var BeVerbose = options.verbose;



var Numbase32 = new Nibbler({
    dataBits: 20,
    codeBits: b32cbits,
    keyString: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',
    pad: '',
    arrayData: true
});

var ProxyOwner = "."+options.dnsname;

var Services = {
	s:{host:'localhost',port:1337}
}


var ConnectionPool = [];
  
var UseTcp = false;
if(UseTcp){
	tcpserver = dns.createTCPServer();
}
function PrintInfo(VerbTxT){
    if(BeVerbose){
        var now = new Date();
        console.error(now.getHours()+':'+now.getMinutes()+':'+now.getSeconds()+' '+VerbTxT);
    }
}

var onMessage = function (request, response) {
  var i;
  
  PrintInfo("# Got query from: "+request._socket._remote.address+" with: "+request.question.length+" question(s)")
  
  //A UDP dns answerpacket may not exced 512 bytes
  var RemaningChars = 500;  //512-12 The static part of a dns response is 12 bytes
  for(qt in response.question){
		RemaningChars -= response.question[qt].name.length + 8;
  }
  //Do this once per dns question
  for(x in request.question){
    
    //A question to one of the services that we support should look somthing
    //like: base32data.base32data.MetaData.PacketData.serviceID.dnsproxy.example.com
    var QuestionName = request.question[x].name;
  	var IsToUs = QuestionName.lastIndexOf(ProxyOwner);

    //Does the question end with our Special Domain
  	if(IsToUs != -1 && IsToUs == (QuestionName.length - ProxyOwner.length)){
  		
  		//Split the question in to its subdomains
  		var DataDomains = QuestionName.substr(0,IsToUs).split('.');
		
		
		
  		HandleQuestionToUs(DataDomains,response.question[x],request.question[x],RemaningChars);
  		
  	}else{
  	    PrintInfo("Question not for us:",request.question[x].name);
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
  PrintInfo("__________________________________________")
};

var onError = function (err, buff, req, res) {
  console.error('ERROR:' ,err.stack);
};

var onListening = function () {
  //console.log('server listening on', this.address());
  //this.close();
};

var onSocketError = function (err, socket) {
  console.log(err);
};

var onClose = function () {
  PrintInfo('server closed', this.address());
};

server.on('request', onMessage);
server.on('error', onError);
server.on('listening', onListening);
server.on('socketError', onSocketError);
server.on('close', onClose);

server.serve(options.port, options.listenip);

if(UseTcp){
	tcpserver.on('request', onMessage);
	tcpserver.on('error', onError);
	tcpserver.on('listening', onListening);
	tcpserver.on('socketError', onSocketError);
	tcpserver.on('close', onClose);

	tcpserver.serve(options.port, options.listenip);
}

function CreateNewSession(cPoolId, ServiceID){
    //we can send about 95 bytes of pure data per Question
    ConnectionPool[cPoolId] = {'Data2ClientPerQuestion':95,'TotalSentToClient':0, 'TotalRecivedFromClient':0, 'data':new Buffer(0), 'socket': null, 'updata':[],'ServiceID':ServiceID,'DowndataID':0,'LastUpdataID':4};
    ConnectionPool[cPoolId].socket = net.connect(Services[ServiceID].port, Services[ServiceID].host,
        function(){
            PrintInfo(cPoolId+ ' Connected to Service server with ServiceID: '+ConnectionPool[cPoolId].ServiceID);
    });

    ConnectionPool[cPoolId].socket.on('data', function(d) {
        PrintInfo(cPoolId+' Got packet with '+d.length+' bytes from Service server with ServiceID: '+ConnectionPool[cPoolId].ServiceID);
        ConnectionPool[cPoolId].data = Buffer.concat([ConnectionPool[cPoolId].data,d]);
        //ConnectionPool[cPoolId].datalen.push(d.length);
        //ConnectionPool[cPoolId].data.push(d);
        //
        if(ConnectionPool[cPoolId].Data2ClientPerQuestion < ConnectionPool[cPoolId].data.length){
            ConnectionPool[cPoolId].socket.pause();
        }
    });

    ConnectionPool[cPoolId].socket.on('error', function(err) {
        PrintInfo(cPoolId+ " Got Error From Service server Connection");
    });
    ConnectionPool[cPoolId].socket.on('close', function() {
        PrintInfo(cPoolId+ ' Service server with ServiceID: '+ConnectionPool[cPoolId].ServiceID+'  disconnected');
    });
}

function HandleClientData(cPoolId,DataDomains,PacketData){
	//A subdomain can only be 63 bytes long so the data is splited in to several subdomains
	var Bs32Data = '';
	for(var i = 0;i<DataDomains.length-2;i++){
		Bs32Data += DataDomains[i];
	}

    //var PacketData = Numbase32.decode(DataDomains[DataDomains.length-3]);
    var UpdataID = PacketData[2];

	if(typeof(ConnectionPool[cPoolId].updata[UpdataID]) == 'undefined'){
		ConnectionPool[cPoolId].updata[UpdataID] = new Buffer(base32.decode(Bs32Data));
		PrintInfo('Recived data width upid: ' + UpdataID);
        if(ConnectionPool[cPoolId].LastUpdataID+1 == UpdataID){
	        while(typeof(ConnectionPool[cPoolId].updata[ConnectionPool[cPoolId].LastUpdataID+1]) != 'undefined'){
		        ConnectionPool[cPoolId].socket.write(
                    ConnectionPool[cPoolId].updata[ConnectionPool[cPoolId].LastUpdataID+1]
                );
                delete ConnectionPool[cPoolId].updata[ConnectionPool[cPoolId].LastUpdataID+1];
                ConnectionPool[cPoolId].LastUpdataID += 1;
	        }
        }
	}else{
		PrintInfo('	Got data width upid: ' + UpdataID + ' More than one time');
	}
}

function HandleServerData(cPoolId, responseQuestion,RemaningChars){

	var TotalBytes = 0;


	var CharsPerAnswer = 254;//An answer can only hold 254 Chars
	//While we have Data in the buffers and the dns answer is not to long
	while(ConnectionPool[cPoolId].data.length != 0 && RemaningChars > 0){
	
	
		var UseDownID = ConnectionPool[cPoolId].DowndataID;
		var DatArrs = [];
	
	
		//Numbase32.encode([Math.round(Math.random()*100000)]);
		var NameToUse = responseQuestion.name;
		var MetaToClient = cPoolId+"."+UseDownID+'.'+ConnectionPool[cPoolId].data.length+':';
	
		var CharsInAnswer = Math.min(CharsPerAnswer,RemaningChars)-(13+MetaToClient.length);//There is 13 static bytes in a txt record
	
		if( 0 < CharsInAnswer){
            var MaxBytesinAnswer =  Math.floor(CharsInAnswer *(6/8));
            var BytesinAnswer =  Math.min(MaxBytesinAnswer, ConnectionPool[cPoolId].data.length);
            TotalBytes += BytesinAnswer;

			DatArrs.push(MetaToClient + ConnectionPool[cPoolId].data.slice(0,BytesinAnswer).toString('base64'));
			ConnectionPool[cPoolId].data = ConnectionPool[cPoolId].data.slice(BytesinAnswer);
			ConnectionPool[cPoolId].DowndataID++;
            if(ConnectionPool[cPoolId].Data2ClientPerQuestion > ConnectionPool[cPoolId].data.length){
                ConnectionPool[cPoolId].socket.resume();
            }


			//The loop is unnececary
			for(DPA in DatArrs){
				//console.error('Answer',DatArrs[DPA]);
				RemaningChars -= DatArrs[DPA].length+13;//A answer costs some static bytes
				response.answer.push(dns.TXT({
					name: NameToUse,
					data: DatArrs[DPA],
					ttl: 1
				}));
			}
		}else{
			break;
		}
	}
	if(TotalBytes != 0){
		PrintInfo("	Sent "+TotalBytes+" bytes to Client");
		ConnectionPool[cPoolId].TotalSentToClient += TotalBytes;
	}
	return(RemaningChars);
}

function HandleQuestionToUs(DataDomains,responseQuestion,requestQuestion,RemaningChars){
	//is the question intended for one of the services we support
  	if(DataDomains.length > 1){
		var ServiceID = DataDomains[DataDomains.length-1];
		if(typeof(Services[ServiceID]) != 'undefined'){
		
  			//which Socket we wan't 
  			var PacketData = Numbase32.decode(DataDomains[DataDomains.length-2]);
            if(PacketData.length < 3){
                PrintInfo('	Data recived from client is corrupt. atleast cPoolId, LastRecivedID, DnsUpId and requestcounter needs to be set in a request');
            }else{
  			    var cPoolId = PacketData[0];
  			    var LastRecivedID = PacketData[1];
  			    var RequestCounter = PacketData[3];
				PrintInfo('	question regarding session: '+cPoolId);
			
	  			
	  			if(typeof(ConnectionPool[cPoolId]) == 'undefined'){
					//If The ConnectionPoolID was unknown we create a connection with that id
                    if(RequestCounter == 0){
                        PrintInfo("	this is a new session to service "+ServiceID+" establishing new connection to service server");
                        CreateNewSession(cPoolId, ServiceID);
                        
                    }else{
                        PrintInfo("Got a new cPoolId where the request counter was not 0. Probably a replay of dead session");
                    }
	  			}else{
					//The Connection Already exists in the connection pool
				
	  				/*
	  				############################################################
	  				Handle upData from The client
	  				############################################################
	  				*/
	  				if(DataDomains.length > 2 && typeof(PacketData[2]) != 'undefined'){
						//When there is updata there is more than 2 extra subdomains
						HandleClientData(cPoolId,DataDomains,PacketData);
	  				}
			
	  				/*
	  				############################################################
	  				Submit Data to The client
	  				############################################################
	  				*/
			
	  				RemaningChars = HandleServerData(cPoolId, responseQuestion, RemaningChars);
					
	  			}
            }
  		}else{
            PrintInfo("Client ask for a service that we dont support:",requestQuestion.name);
  			/*
  			response.answer.push(dns.TXT({
    			name: "Unknown.service.alias",
    			data: '127.0.0.2',
    			ttl: 1,
  			}));*/
  		}
	}else{
        PrintInfo("Question does not apper to be corectly formated:",requestQuestion.name);
  		/*
  		response.answer.push(dns.TXT({
    		name: "to.few.subdomain.entrys",
    		data: '127.0.0.2',
    		ttl: 1,
  		}));*/
  	}
	return(RemaningChars);
}
