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


var base32 = new Nibbler({
    dataBits: 8,
    codeBits: 5,
    keyString: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',
    pad: '',
    arrayData: true
});


var BeVerbose = options.verbose;



var Numbase32 = new Nibbler({
    dataBits: 20,
    codeBits: 5,
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

var onMessage = function (request, response) {
  var i;
  
  if(BeVerbose)
 	 console.error("# Got query from: "+request._socket._remote.address+" with: "+request.question.length+" question(s)")
  //Do this once per dns question
  for(x in request.question){
    
    //A question to one of the services that we support should look somthing
    //like: base32data.base32data.MetaData.PacketData.serviceID.dnsproxy.example.com
    var QuestionName = request.question[x].name;
  	var IsToUs = QuestionName.lastIndexOf(ProxyOwner);

    //Does the question end with our Special Domain?
  	if(IsToUs != -1 && IsToUs == (QuestionName.length - ProxyOwner.length)){
  		
  		//Split the question in to its subdomains
  		var SubDomains = QuestionName.substr(0,IsToUs).split('.');
  		
  		//is the question intended for one of the services we support
	  	if(SubDomains.length > 1){
			var ServiceID = SubDomains[SubDomains.length-1];
			if(typeof(Services[ServiceID]) != 'undefined'){
  			
	  			//which Socket we wan't 
	  			var PacketData = Numbase32.decode(SubDomains[SubDomains.length-2]);
	            if(PacketData.length != 3){
	                console.error('	Data recived from client is corrupt.');
	            }else{
	  			    var cPoolId = PacketData[1];
		  			var answercounter = 0;
					console.error('	question regarding session: '+cPoolId);
  				
		  			//If The ConnectionPoolID was unknown we create a connection with that id
		  			if(typeof(ConnectionPool[cPoolId]) == 'undefined'){
					    if(BeVerbose)
							console.error("	this is a new session to service "+ServiceID+" establishing new connection to service server");
						
                        //we can send about 100 bytes of pure data per request
		  				ConnectionPool[cPoolId] = {'Data2ClientPerQuestion':100,'TotalSentToClient':0, 'TotalRecivedFromClient':0, 'data':[], 'datalen':[], 'socket': null, 'updata':[],'ServiceID':ServiceID,'DowndataID':0};
		  				ConnectionPool[cPoolId].socket = net.connect(Services[ServiceID].port, Services[ServiceID].host,
		                    function(){
		                        console.error(cPoolId+ ' Connected to Service server with ServiceID: '+ConnectionPool[cPoolId].ServiceID);
		                });
                	
		                ConnectionPool[cPoolId].socket.on('data', function(d) {
		                	console.error(cPoolId+' Got packet with '+d.length+' bytes from Service server with ServiceID: '+ConnectionPool[cPoolId].ServiceID);
		                	ConnectionPool[cPoolId].datalen.push(d.length);
		                	ConnectionPool[cPoolId].data.push(d);
                            var InLocalBuffer = 0;
                            for(var i in ConnectionPool[cPoolId].datalen) { InLocalBuffer += ConnectionPool[cPoolId].datalen[i]; }
                            if(ConnectionPool[cPoolId].Data2ClientPerQuestion < InLocalBuffer){
                                ConnectionPool[cPoolId].socket.pause();
                            }
		                });
                	
		                ConnectionPool[cPoolId].socket.on('error', function(err) {
		        			console.error(cPoolId+ " Got Error From Service server Connection", err);
		    			});
		    			ConnectionPool[cPoolId].socket.on('close', function() {
		        			console.error(cPoolId+ ' Service server with ServiceID: '+ConnectionPool[cPoolId].ServiceID+'  disconnected');
		        		});
                	
		  			}else{//The Connection Already exists in the connection pool
  					
		  				/*
		  				############################################################
		  				Handle upData from The client
		  				############################################################
		  				*/
		  				if(SubDomains.length > 2){//When there is updata there is more than 2 extra subdomains
  						
  						
		  					//A subdomain can only be 63 bytes long so the data is splited in to several subdomains
		  					var Bs32Data = '';
		  					for(var i = 0;i<SubDomains.length-3;i++){
		  						Bs32Data += SubDomains[i];
		  					}
  					
		  					var MetaData = Numbase32.decode(SubDomains[SubDomains.length-3]);
		  					var DataLeft = MetaData[0];
		  					var TotalLength = MetaData[1];
                    
		                    //var PacketData = Numbase32.decode(SubDomains[SubDomains.length-3]);
		                    var UpdataID = PacketData[0];
  					
		  					//We buffer the recived data until we have the entire tcp packet
		  					if(typeof(ConnectionPool[cPoolId].updata[UpdataID]) == 'undefined'){
		  						ConnectionPool[cPoolId].updata[UpdataID] = [];
		  					}
		  					if(typeof(ConnectionPool[cPoolId].updata[UpdataID][TotalLength-DataLeft]) == 'undefined'){
		  						ConnectionPool[cPoolId].updata[UpdataID][TotalLength-DataLeft] = Bs32Data;
		  					}else{
		  						console.error('	Got data at offset: '+ (TotalLength-DataLeft)+' More than one time');
		  					}
  							var RecivedInQuestion = ((Bs32Data.length/8.0)*5.0);
		  					var DatRecived = 0.0;//DataLeft - Bs32Data.length;
							var BytesRecvied = 0.0;
		  					//When We recive the last part send it away
		  					for(DatOffset in ConnectionPool[cPoolId].updata[UpdataID]){
		  						DatRecived += ConnectionPool[cPoolId].updata[UpdataID][DatOffset].length;
		  					}
							var BytesDatRecived = (DatRecived/8.0)*5.0;
		  					if(DatRecived == TotalLength){
  							
		  						var UpData = new Buffer(base32.decode(ConnectionPool[cPoolId].updata[UpdataID].join('')));
								BytesRecvied = UpData.length;
								ConnectionPool[cPoolId].TotalRecivedFromClient += BytesRecvied;
		  						//process.stderr.write(ConnectionPool[cPoolId].updata[UpdataID], 'utf8');
  						
		  						delete ConnectionPool[cPoolId].updata[UpdataID];
		  						//console.error(UpData.toString("base64"))
		  						console.error('	Recived '+RecivedInQuestion+' bytes Proxyed full packet with '+BytesRecvied+' bytes to server');
		  						ConnectionPool[cPoolId].socket.write(UpData);
		  					}else{
		  						console.error('	Recived '+RecivedInQuestion+' bytes the client will send another '+((DataLeft/8.0)*5.0)+' bytes and we have recived '+BytesDatRecived+" The client has sent: "+(TotalLength-DataLeft)+"  of "+ TotalLength +" bytes in the packet");
		  					}
  					
		  					/*else{
		  						console.error(cPoolId, "The client has sent its last pice of data but we have not gotten the full tcp packet. We must have missed a dns request or gotten it in wrong order");
		  						console.error(ConnectionPool[cPoolId].updata[UpdataID].length,MetaData);
		  					}*/
		  					//}
  					
  					
  				
		  				}
  				
		  				/*
		  				############################################################
		  				Submit Data to The client
		  				############################################################
		  				*/
  				
		  				//A UDP dns answerpacket may not exced 512 bytes
		  				var RemaningBytes = 500;  //512-12 The static part of a dns response is 12 bytes
		  				for(qt in response.question){
  						
		  					//console.error("Names", response.question[qt].name);
  						
		  					RemaningBytes -= response.question[qt].name.length + 6;
		  				}
  					
		  				//console.error("RemaningBytes", RemaningBytes);
		  				var TotalBytes = 0;
  					
  					
		  				var BytesPerAnswer = 255;//An answer can only hold 255 bytes
		  				//While we have Data in the buffers and the dns answer is not to long
		  				while(ConnectionPool[cPoolId].data.length != 0 && RemaningBytes > 0){
  						
  						
		  					//We wait with converting the data to base64 until now to save memory
		  					if(typeof(ConnectionPool[cPoolId].data[0]) != 'string'){
		  						ConnectionPool[cPoolId].data[0] = ConnectionPool[cPoolId].data[0].toString('base64')
                                //console.error('_',ConnectionPool[cPoolId].data[0],'_')
							    TotalBytes += ConnectionPool[cPoolId].data[0].length;
		  						ConnectionPool[cPoolId].datalen[0] = ConnectionPool[cPoolId].data[0].length
		  					}
  						
  						
		  					//Save stuff to put in the answer so that we have it if the current buffer is removed below
		  					var RemLength = ConnectionPool[cPoolId].data[0].length;
		  					var UseDownID = ConnectionPool[cPoolId].DowndataID;
                            var PacketLen = ConnectionPool[cPoolId].datalen[0];
  						
		  					var DatArrs = [];
  						
  						
		  					//Numbase32.encode([Math.round(Math.random()*100000)]);
		  					var NameToUse = response.question[x].name;
		  					var MetaToClient = RemLength+"."+UseDownID+"."+cPoolId+'.'+PacketLen+':';
  						
		  					var BytesInAnswer = Math.min(BytesPerAnswer,RemaningBytes)-NameToUse.length-12-MetaToClient.length;//There is 12 static bytes in a txt record
  						
		  					if( 0 < BytesInAnswer){
		  						//If we have more than one answer can send split the data
		  						if(ConnectionPool[cPoolId].data[0].length > BytesInAnswer){
		  							DatArrs.push(MetaToClient+ConnectionPool[cPoolId].data[0].substr(0,BytesInAnswer));
		  							ConnectionPool[cPoolId].data[0] = ConnectionPool[cPoolId].data[0].substr(BytesInAnswer);
		  						}else{
		  							DatArrs.push(MetaToClient+ConnectionPool[cPoolId].data.shift());
                                    ConnectionPool[cPoolId].datalen.shift();
                                    var InLocalBuffer = 0;
                                    for(var i in ConnectionPool[cPoolId].datalen) { InLocalBuffer += ConnectionPool[cPoolId].datalen[i]; }
                                    if(ConnectionPool[cPoolId].Data2ClientPerQuestion > InLocalBuffer){
                                        ConnectionPool[cPoolId].socket.resume();
                                    }
		  							ConnectionPool[cPoolId].DowndataID++;
		  						}
  					
  					
		  						//The loop is unnececary
		  						for(DPA in DatArrs){
		  							//console.error('Answer',DatArrs[DPA]);
		  							RemaningBytes -= DatArrs[DPA].length+NameToUse.length+12;//A answer costs some static bytes
		  							response.answer.push(dns.TXT({
		  								name: NameToUse,
		    							data: DatArrs[DPA],
		    							ttl: 1
		  							}));
		  							answercounter++;
		  						}
		  					}else{
		  						break;
		  					}
		  				}
						if(TotalBytes != 0){
							console.error("	Sent "+TotalBytes+" bytes to Client");
							ConnectionPool[cPoolId].TotalSentToClient += TotalBytes;
						}
		  			}
	            }
	  		}else{
  	            console.error("Client ask for a service that we dont support:",request.question[x].name);
	  			/*
	  			response.answer.push(dns.TXT({
	    			name: "Unknown.service.alias",
	    			data: '127.0.0.2',
	    			ttl: 1,
	  			}));*/
	  		}
		}else{
  	        console.error("Question does not apper to be corectly formated:",request.question[x].name);
	  		/*
	  		response.answer.push(dns.TXT({
	    		name: "to.few.subdomain.entrys",
	    		data: '127.0.0.2',
	    		ttl: 1,
	  		}));*/
	  	}
  	}else{
  	    console.error("Question not for us:",request.question[x].name);
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
  if(BeVerbose)
 	 console.error("__________________________________________")
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
  console.log('server closed', this.address());
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
