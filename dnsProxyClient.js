var dns = require('native-dns'),
	fs = require('fs'),
	stdio = require('stdio'),
	dnt = require('./dnsProxyCommon.js');

var argDescr = {
	'dnsname': {
		key: 'd',
		args: 1,
		description: 'The dns name of the dns server example: dns.example.com',
		mandatory: true
	},
	'service': {
		key: 's',
		args: 1,
		description: 'The service that we want to connect to.',
		mandatory: true
	},
	'resolver': {
		key: 'r',
		args: 1,
		description: 'The ip number of the resolver server we want to use, default is read from /etc/resolv.conf'
	},
	'port': {
		key: 'p',
		args: 1,
        default: 53,
        pharse: parseInt,
		description: 'The resolver server port the default is 53'
	},
	'timing': {
		key: 't',
		args: 1,
        default: 500,
        pharse: parseInt,
		description: 'How often to normaly do dns requests in ms. 500 is default'
	},
	'mintiming': {
		key: 'ti',
		args: 1,
        default: 50,
        pharse: parseInt,
		description: 'Never send request faster than this(to lessen strain on resolvers) in ms. 50 is default'
	},
	'maxtiming': {
		key: 'ta',
		args: 1,
        default: 15000,
        pharse: parseInt,
		description: 'Never send request slower than this (to slow is not good) in ms. 15000 is default'
	},
	'throttle': {
		key: 'tr',
		args: 1,
        default: 100,
        pharse: parseInt,
		description: 'How much to incresse the latency per request when there is no activity in ms. 100 is default'
	},
	'UseDualQuestion': {
		key: 'q',
		description: 'Use two questions per request. Some dns servers dont allow that. however if it is supported one can double the up bandwith'
	},
	'verbose': {
		key: 'v',
		description: 'Print more information to stderr'
	}
};

//Pharse Arguments
var options = stdio.getopt(argDescr);

if (!options.resolver) {
	options.resolver = '127.0.0.1';
	var Lines = fs.readFileSync('/etc/resolv.conf').toString().split("\n");
	for (nr in Lines) {
		var opts = Lines[nr].split(' ');
		if (opts[0] == 'nameserver') {
			options.resolver = opts[1];
		}
	}
}

//Set Default Argument Values and pharse them
for(ArgName in argDescr){
    if(!options[ArgName] && argDescr[ArgName].default){
        options[ArgName] = argDescr[ArgName].default;
    }
    
    if(argDescr[ArgName].pharse && options[ArgName]){
        options[ArgName] = argDescr[ArgName].pharse(options[ArgName]);
    }
}


/*
A DNS name can be at max 253 (some places say 255 but i think they count with the start and stop bytes) bytes long
Then we remove 1 due to the dot before "options.dnsname" and 20 the header length
also each subdomain may maximumly be 63 bytes which means that we need to insert dots.
*/
var MaxDNSNameData_Len = 253 - (options.dnsname.length + 1 + 20);
MaxDNSNameData_Len -= Math.ceil(MaxDNSNameData_Len/63);
var MaxDNSNameRawData_Len = Math.floor(MaxDNSNameData_Len * (dnt.b32cbits / 8));

//Create A random Number that will be the Id of our session
var SessionID = false;
var SubmitedBytes_Len = 0;
var NextByte_Len = 0;

var DataFromUser_Arr = [];
var DataFromServer_Arr = [];


//Save All Data from STDIN TO DataFromUser_Arr
process.stdin.on('data', function(UserData_Buf) {
    var SavedData_Len = 0;
    if(DataFromUser_Arr.length != 0){
        if(DataFromUser_Arr[DataFromUser_Arr.length-1].length < MaxDNSNameRawData_Len){//If the last one is not filed up
            var MissingData_Len = MaxDNSNameRawData_Len - DataFromUser_Arr[DataFromUser_Arr.length-1].length;
            SavedData_Len = Math.min(MissingData_Len, DataFromUser_Arr[DataFromUser_Arr.length-1].length);
            DataFromUser_Arr[DataFromUser_Arr.length-1] = Buffer.concat([DataFromUser_Arr[DataFromUser_Arr.length-1], UserData_Buf.slice(0, SavedData_Len)]);
        }
    }
    
    while(SavedData_Len < UserData_Buf.length){
        var BytesToShave = Math.min(MaxDNSNameRawData_Len, UserData_Buf.length - SavedData_Len);
        DataFromUser_Arr.push(UserData_Buf.slice(SavedData_Len, SavedData_Len + BytesToShave));
        SavedData_Len += BytesToShave;
    }
});

process.stdin.on('end', function() {
	console.error("Report to server that we are exiting");
	process.exit();
});

//Start Capturing from stdin
process.stdin.resume();

var NextDNSRequest_TimeOut = setTimeout(MainLoop, 1);

//Ask Server to start a new Session
var Packet2Server = new dnt.ClientPacket();
Packet2Server.commando = 2;
Packet2Server.data = new Buffer(options.service);
DnsLookup(Packet2Server.GetBinData()+"."+options.dnsname)

function MainLoop(){
    //Only Conntact The server after we have acured a SessionID
    if(SessionID !== false){
        var Packet2Server = new dnt.ClientPacket();
        Packet2Server.sessionID = SessionID;
        Packet2Server.offset = SubmitedBytes_Len;
        Packet2Server.recivedoffset = NextByte_Len;
        Packet2Server.commando = 3;
        if(DataFromUser_Arr.length != 0){
            Data2Send = DataFromUser_Arr.shift();
            Packet2Server.commando = 1;
            Packet2Server.data = Data2Send;

            SubmitedBytes_Len += Data2Send.length;
        } 
        DnsLookup(Packet2Server.GetBinData()+"."+options.dnsname)
    } 
    NextDNSRequest_TimeOut = setTimeout(MainLoop, options.timing);
}


function DnsLookup(DnsName_Str){
    
	var req = dns.Request({
		question: dns.Question({
            name: DnsName_Str,
            type: 'TXT',
             class: 1
        }),
		server: {
			address: options.resolver,
			port: options.port,
			type: 'udp'
		},
		cache: false,
		timeout: 7000
	});

	req.on('timeout', function() {
        console.error("timed out")
		//var redoname = this.question.name;
		//setTimeout(function() {
			//SubmitDnsRequest(redoname);
		//}, 500);
	});

	req.on('message', function(err, response) { //err should be null
		if (err != null) {
			console.error("Got an error:", err);
		}

        for(answerID in response.answer){
            var RecivedPacket = new dnt.ServerPacket(response.answer[answerID].data);
            switch(RecivedPacket.commando){
                case 2://New Session
                    if(SessionID === false){
                        SessionID = parseInt(RecivedPacket.data.toString());
                    }else{
			            console.error("Got a session id twice.");
                    }
                    break;
                case 3://Empty response
                    break;
                case 1://Recived data from server
                    DataFromServer_Arr[RecivedPacket.offset] = RecivedPacket.data;
                    for(datOffset in DataFromServer_Arr){
                        if(NextByte_Len == datOffset){
                            NextByte_Len += DataFromServer_Arr[datOffset].length;
                            process.stdout.write(DataFromServer_Arr[datOffset]);
                        }
                    }
        
                    break;
                case 5://Server error
			        console.error("Server reported error: "+RecivedPacket.data.toString());
                    process.exit();
                    break;
                default:
                    console.error("Unknown commando: "+RecivedPacket.commando);
                    process.exit();
                    break;
            }
        }
    });
	req.send();
}

/*
//process.exit();

var CurrentTimeOut = setTimeout(HandleDomainNameQue, 1);
var CurrentActivity = 0;
var WhenWasTheLastRequestSubmited = 0;


function HandleDomainNameQue(Activity) { //when Activity is on we reset the timer and sends next query soner than scheduled
	var When2RunNextTime = options.timing;

	if (DomainNameQue.length != 0) {
		Activity = true;
	}
	clearTimeout(CurrentTimeOut);

	//if somthing has happend here or on the server
	if (Activity) {
		CurrentTime = (new Date()).getTime();
		CurrentActivity = 0;

		if (CurrentTime - WhenWasTheLastRequestSubmited >= options.mintiming) {
			SubmitRequestFromDomainNameQue();
			WhenWasTheLastRequestSubmited = (new Date()).getTime();
		} else {
			When2RunNextTime = options.mintiming - (CurrentTime - WhenWasTheLastRequestSubmited);
		}
	} else {
		SubmitRequestFromDomainNameQue();
		WhenWasTheLastRequestSubmited = (new Date()).getTime();
		CurrentActivity = Math.min(CurrentActivity + options.throttle, options.maxtiming);
		When2RunNextTime = options.timing + CurrentActivity;
	}
	CurrentTimeOut = setTimeout(HandleDomainNameQue, When2RunNextTime);
}


function Add2DomainNameQue(req1, req2) {
	DomainNameQue.push([req1, req2])
	RequestCounter++;
}

function SubmitRequestFromDomainNameQue() {
	if (DomainNameQue.length == 0) {
		SubmitDnsRequest();
	} else {
		var nextRequest = DomainNameQue.shift()
		SubmitDnsRequest(nextRequest[0], nextRequest[1]);
	}
}

function InputData2DomainNames(InputData) {

	var SubmitedBytes = 0;
	while (InputData.length != SubmitedBytes) {

		var DomainName = InputData2DomainName();
		var SecondDomainName;

		//If We should use the secound query
		if (options.UseDualQuestion && InputData.length != SubmitedBytes) {
			SecondDomainName = InputData2DomainName();
		}
		Add2DomainNameQue(DomainName, SecondDomainName);
	}
	SubmitedTotData += SubmitedBytes;

	function InputData2DomainName() {
		var PacketData = Numbase32.encode([ConnectionIDNum, LastRecivedID, DNSPacketID, RequestCounter]);
		var DomainNameOrg = PacketData + AppendStr;

		var UsableChars = Math.abs(Math.floor(MaxDataBytesInTxt - DomainNameOrg.length));
		var Bytes2Use = Math.min(InputData.length - SubmitedBytes, Math.floor(UsableChars * (b32cbits / 8)));

		var ActualData = base32.encode(InputData.slice(SubmitedBytes, SubmitedBytes + Bytes2Use));
		SubmitedBytes += Bytes2Use;

		var FormatedData = '';
		while (ActualData.length > 63) {
			FormatedData += ActualData.substr(0, 63) + ".";
			ActualData = ActualData.substr(63)
		}
		FormatedData += ActualData + ".";
		DNSPacketID++;
		return (FormatedData + DomainNameOrg);
	}
}

function SubmitDnsRequest(DomainName, SecondDomainName) {

	if (typeof(DomainName) == 'undefined') {
		var PacketData = Numbase32.encode([ConnectionIDNum, LastRecivedID, DNSPacketID, RequestCounter]);
		RequestCounter++;
		DomainName = PacketData + AppendStr;
	}

	var question = dns.Question({
		name: DomainName,
		type: 'TXT',
		class: 1
	});

	var req = dns.Request({
		question: question,
		server: {
			address: ResolveServer,
			port: ResolveServerPort,
			type: 'udp'
		},
		cache: false,
		timeout: 7000
	});

	if (typeof(SecondDomainName) != 'undefined') {
		var question2 = dns.Question({
			name: SecondDomainName,
			type: 'TXT',
			class: 1
		});
		req.questions = [req.question, question2];
	}

	req.on('timeout', function() {
		var redoname = this.question.name;
		setTimeout(function() {
			SubmitDnsRequest(redoname);
		}, 500);
	});

	req.on('message', function(err, answer) { //err should be null
		if (err != null) {
			console.error("Got an error:", err);
		}


		answer.answer.forEach(function(a) {
			if (a.type == 16) {

				var Splitpos = a.data.indexOf(':');
				if (Splitpos == -1) {
					console.error("ERROR answer not correctly formated could not find the split position got back the following answer data:", a.data);
                    process.exit(3);
				}
				var Parts = a.data.substr(0, Splitpos);
				a.data = a.data.substr(Splitpos + 1);
				Parts = Parts.split(".");

				if (Parts.length > 2 && ConnectionIDNum == Parts[0]) {
					var RequestMoreData = false;
					if (typeof(DownData[Parts[1]]) == 'undefined') {
						DownData[Parts[1]] = a.data
						if (a.data.length < Parts[2]) {
							RequestMoreData = true;
						}
					} else {
						console.error("ERROR got back duplicates of a request with DownDataID:", Parts[1], a);
					}

					FinishedDownData[Parts[1]] = Parts[1];
					for (key in FinishedDownData) {
						var dwid = FinishedDownData[key];
						if (dwid == NextDownDataID) {
							process.stdout.write(DownData[dwid], 'base64');
							LastRecivedID = dwid;
							delete DownData[dwid];
							delete FinishedDownData[key];
							NextDownDataID += 1;
						}
					}
					if (RequestMoreData) {
						HandleDomainNameQue(true);
					}
				} else {
					console.error("ERROR answer not correctly formated to few subdomains got back the following answer data:", a.data);
                    process.exit(2);
				}
			} else {
				console.error("ERROR answer not correctly formated it is not of type 16 got back the following answer:", a.name);
                process.exit(1);
			}
		});
	});
	req.send();
}
*/
