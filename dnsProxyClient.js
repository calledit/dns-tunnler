
var dns = require('native-dns'),
  stdio = require('stdio');

var Nibbler = require('./Nibbler.js').Nibbler;

var options = stdio.getopt({
    'dnsname': {key: 'd', args: 1, description: 'The dns name of the dns server example: dns.example.com', mandatory: true},
    'service': {key: 's', args: 1, description: 'The service that we want to connect to.', mandatory: true},
    'resolver': {key: 'r',args:1, description: 'The ip number of the resolver server we want to use, default is 127.0.0.1'},
    'port': {key: 'p', args: 1, description: 'The resolver server port the default is 53'},
    'timing': {key: 't', args: 1, description: 'How often to do dns requests in ms. 500 is default'},
    'UseDualQuestion': {key: 'q', description: 'Use two questions per request. Some dns servers dont allow that. however if it is supported one can double the up bandwith'},
    'verbose': {key: 'v', description: 'Print more information to stderr'}
});

if(!options.resolver){
    options.resolver = '127.0.0.1';
}
if(!options.timing){
    options.timing = 500;
}
if(!options.port){
    options.port = 53;
}

var ResolveServer = options.resolver;
var ResolveServerPort = options.port;
var ServiceAlias = options.service;
var ProxyOwner = options.dnsname;


var RequestCounter = 0;
var UpdataID = 0;

var base32 = new Nibbler({
    dataBits: 8,
    codeBits: 5,
    keyString: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',
    pad: '',
    arrayData: true
});

var Numbase32 = new Nibbler({
    dataBits: 20,
    codeBits: 5,
    keyString: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789',
    pad: '',
    arrayData: true
});

var DownData = [];
var FinishedDownData = [];
var NextDownDataID = 0;

//Create A random Number that will be the Id of our session
var ConnectionIDNum = Math.round(Math.random()*100000);
var SubmitedTotData = 0;

var AppendStr = '.'+ServiceAlias+'.'+ProxyOwner
var RequestQue = [];

//Handle Input from the ssh client
process.openStdin();
process.stdin.resume();


//Force Raw mode i someone might wan't this
//require('tty').setRawMode(true);


//When we get data from the ssh Client
process.stdin.on('data', function (chunk) {
	SubmitBuffer(chunk);
    CurrentTime = (new Date()).getTime();
    if(CurrentTime-LastRequest > options.timing){
        CurrentActivity = 0;
        clearTimeout(CurrentTimeOut);
        HandleRequestTiming();
    }
});

process.stdin.on('end', function () {
  process.exit();
});

var CurrentTimeOut = setTimeout(HandleRequestTiming,1);
var CurrentActivity = 0;
var LastRequest = 0;

function HandleRequestTiming(){
    HandleQue();
    LastRequest = (new Date()).getTime();
    CurrentTimeOut = setTimeout(HandleRequestTiming, options.timing+CurrentActivity);
    CurrentActivity += 10;
}

HandleRequestTiming();

function AddToQue(req1, req2){
    RequestQue.push([req1, req2])
}

function HandleQue(){
    if(RequestQue.length == 0){
        doDnsRequest();
    }else{
        var nextRequest = RequestQue.shift()
        doDnsRequest(nextRequest[0], nextRequest[1]);
    }
}

function SubmitBuffer(SendBuffer){
	
	//Convert The Buffer to Base32 text
	var DataB = base32.encode(SendBuffer);
	var DataTosend = DataB.length;
	/*
    	A DNS name can be at max 253 (some places say 255 but i think they count with the start and stop bytes) bytes long and
    	each subdomain maximumly 63 bytes which means that we need to insert 4 dots thats where 249 comes from
    	*/
	var MaxDataBytesInTxt = 249;
	
	while(DataB.length != 0){
		var encodedLength = Numbase32.encode([DataB.length, DataTosend]);
		var PacketData = Numbase32.encode([UpdataID, ConnectionIDNum, SubmitedTotData]);
		var QustDataOrg = encodedLength+'.'+PacketData+AppendStr;
		
		var Bytes2Use = Math.min(DataB.length, Math.abs(Math.floor(MaxDataBytesInTxt-QustDataOrg.length)));
		
		var ActualData = DataB.substr(0, Bytes2Use);
		DataB = DataB.substr(Bytes2Use);
		
		
		var FormatedData = '';
		while(ActualData.length > 63){
			FormatedData += ActualData.substr(0,63) + ".";
			ActualData = ActualData.substr(63)
		}
		FormatedData += ActualData + ".";
		var QustData = FormatedData + QustDataOrg;
		
		
		var QsDat2;

		//If We should use the secound query
		if(options.UseDualQuestion && DataB.length != 0){
			encodedLength = Numbase32.encode([DataB.length, DataTosend]);
		    	PacketData = Numbase32.encode([UpdataID,ConnectionIDNum, SubmitedTotData]);
			QustDataOrg = encodedLength+'.'+PacketData+AppendStr;
			Bytes2Use = Math.min(DataB.length, Math.abs(Math.floor(MaxDataBytesInTxt-QustDataOrg.length)));
			
			ActualData = DataB.substr(0, Bytes2Use);
			DataB = DataB.substr(Bytes2Use);
			
			FormatedData = '';
			while(ActualData.length > 63){
				FormatedData += ActualData.substr(0,63) + ".";
				ActualData = ActualData.substr(63)
			}
			FormatedData += ActualData + ".";
			QsDat2 = FormatedData + QustDataOrg;
		}
		AddToQue(QustData,QsDat2);
		
	}
	SubmitedTotData += DataTosend;
	UpdataID++;
}

function doDnsRequest(QustData,SecQuestData){
	
	if(typeof(QustData) == 'undefined'){
		var PacketData = Numbase32.encode([RequestCounter, ConnectionIDNum, SubmitedTotData]);
		QustData = PacketData+'.'+ServiceAlias+'.'+ProxyOwner;
	}
	
	
	//console.error("OK", QustData, SecQuestData);
	
	var question = dns.Question({
	  name: QustData,
	  type: 'TXT',
	  class: 1
	});
	
	var req = dns.Request({
	  question: question,
	  server: { address: ResolveServer, port: ResolveServerPort, type: 'udp' },
	  cache: false,
	  timeout: 7000
	});
	
	if(typeof(SecQuestData) != 'undefined'){
		var question2 = dns.Question({
	  		name: SecQuestData,
	  		type: 'TXT',
	  		class: 1
			});
		req.questions = [req.question,question2];
	}
	
	req.on('timeout', function () {
		console.error('Timeout in making request');
		console.error("ERROR", QustData, SecQuestData);
	});
	
	req.on('message', function (err, answer) {//err should be null
		if(err != null){
			console.error("Got an error:",err);
		}
		answer.answer.forEach(function (a) {
			//console.error("Got Answer:",a.name);
			if(a.type == 16){
				
				var Splitpos = a.data.indexOf(':');
				if(Splitpos == -1){
					console.error("could not find split pos ERROR");
				}
				var Parts = a.data.substr(0,Splitpos);
				a.data = a.data.substr(Splitpos+1);
				Parts = Parts.split(".");
				
				if(typeof(Parts[2]) != 'undefined' && ConnectionIDNum == Parts[2]){
					if(typeof(DownData[Parts[1]]) == 'undefined'){
						DownData[Parts[1]] = []
					}
                			if(typeof(DownData[Parts[1]][Parts[3]-Parts[0]]) != 'undefined'){
						console.error("ERROR got back duplicates of a packet part");
					}
					DownData[Parts[1]][Parts[3]-Parts[0]] = a.data;
					
					var DataInSoFar = DownData[Parts[1]].join('');
					//If we are expecting more data
					if(Parts[3] != DataInSoFar.length){
                        CurrentActivity();
						//HandleQue();
					}else{
						//process.stderr.write(DownData[Parts[1]], 'base64');
						FinishedDownData[Parts[1]] = Parts[1];
						for(key in FinishedDownData){
							var dwid = FinishedDownData[key];
							if(dwid == NextDownDataID){
								//console.error("ERROR There is Down data ealier than",Parts[1],"in the que:",key,DownData[key] );
								process.stdout.write(DownData[dwid].join(''), 'base64');
								delete DownData[dwid];
								delete FinishedDownData[key];
								NextDownDataID += 1;
							}
						}
					}
				}else{
					console.error("ERROR got back the following answer:", a.name);
				}
			}else{
				console.error("Could not contact proxy server got back the following answer:",a.name);
			}
		});
	});
	
	req.on('end', function () {
		//console.error("End1");
	});
	
	req.send();
	RequestCounter++;
}



