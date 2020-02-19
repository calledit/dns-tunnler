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
		default: 's',
		description: 'The service that we want to connect to. Defaults to s indicating ssh.',
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
	'pooltiming': {
		key: 'po',
		args: 1,
		default: 5000,
		pharse: parseInt,
		description: 'How long the a poll may last. 5000 is default'
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
for (ArgName in argDescr) {
	if (!options[ArgName] && argDescr[ArgName].default) {
		options[ArgName] = argDescr[ArgName].default;
	}

	if (argDescr[ArgName].pharse && options[ArgName]) {
		options[ArgName] = argDescr[ArgName].pharse(options[ArgName]);
	}
}


/*
A DNS name can be at max 253 (some places say 255 but i think they count with the start and stop bytes) bytes long
Then we remove 1 due to the dot before "options.dnsname" and 20 the header length
also each subdomain may maximumly be 63 bytes which means that we need to insert dots.
*/
var MaxDNSNameData_Len = 253 - (options.dnsname.length + 1 + 20);
MaxDNSNameData_Len -= Math.ceil(MaxDNSNameData_Len / 63);
var MaxDNSNameRawData_Len = Math.floor(MaxDNSNameData_Len * (dnt.b32cbits / 8));

//The sessionID is what the client uses to identify itself with it is recived from the server when connecting
var SessionID = false;
var Server_Recived_Bytes_Len = 0;
var BufferdBytes_Len = 0;
var NextByte_Len = 0;
var Time2NextRequest = options.timing;

var DataFromUser_Arr = [];
var DataFromServer_Arr = [];


//Save All Data from STDIN TO DataFromUser_Arr
process.stdin.on('data', function(UserData_Buf) {
	Time2NextRequest = options.timing; //When we recive data from the client we reset the throtheling timouts
	var SavedData_Len = 0;
	//Split up the data we got from the client in to parts of MaxDNSNameRawData_Len or smaller
	while (SavedData_Len < UserData_Buf.length) {
		var BytesToShave = Math.min(MaxDNSNameRawData_Len, UserData_Buf.length - SavedData_Len);
		DataFromUser_Arr[BufferdBytes_Len] = UserData_Buf.slice(SavedData_Len, SavedData_Len + BytesToShave);
		BufferdBytes_Len += BytesToShave;
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
Packet2Server.data = Buffer.from(options.service);
DnsLookup(Packet2Server.GetBinData() + "." + options.dnsname, true)

function MainLoop() {

	clearTimeout(NextDNSRequest_TimeOut); //incase the function was called directly we want to remove the next timed execution of it

	//Only Conntact The server after we have acured a SessionID
	if (SessionID !== false) {
		var Packet2Server = new dnt.ClientPacket();
		Packet2Server.sessionID = SessionID;
		Packet2Server.offset = Server_Recived_Bytes_Len;
		Packet2Server.recivedoffset = NextByte_Len;
		Packet2Server.commando = 3;

		//If the requested data exists
		if (typeof(DataFromUser_Arr[Server_Recived_Bytes_Len]) != 'undefined') {
			var Data2Send = DataFromUser_Arr[Server_Recived_Bytes_Len];
			//Concat as mush data as posible
			while (typeof(DataFromUser_Arr[Server_Recived_Bytes_Len + Data2Send.length]) != 'undefined') {
				if (Data2Send.length + DataFromUser_Arr[Server_Recived_Bytes_Len + Data2Send.length].length > MaxDNSNameRawData_Len) {
					break;
				}
				Data2Send = Buffer.concat([Data2Send, DataFromUser_Arr[Server_Recived_Bytes_Len + Data2Send.length]]);
			}
			Packet2Server.commando = 1;
			Packet2Server.data = Data2Send;

		}
		DnsLookup(Packet2Server.GetBinData() + "." + options.dnsname)
	}
	NextDNSRequest_TimeOut = setTimeout(MainLoop, Time2NextRequest);
	//Increse the throttling, when there is periods of inactivity slow down.
	Time2NextRequest += options.throttle;
	Time2NextRequest = Math.min(options.maxtiming, Time2NextRequest);
}


//make A Dns lookup and handle the response
function DnsLookup(DnsName_Str, Wital) {
	var ErrorOnTimeout = false;
	if (Wital) {
		ErrorOnTimeout = true;
	}
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
		timeout: options.pooltiming + 5000
	});

	req.on('timeout', function() {
		//console.error("timed out")
		if (ErrorOnTimeout) {
			console.error("Message was wital closing down.");
			process.exit();
		}
		//var redoname = this.question.name;
		//setTimeout(function() {
		//SubmitDnsRequest(redoname);
		//}, 500);
	});

	req.on('message', function(err, response) { //err should be null
		if (err != null) {
			console.error("Got an error:", err);
		}

		var LastCommandType = null;
		for (answerID in response.answer) {
			var RecivedPacket = new dnt.ServerPacket(response.answer[answerID].data);
			LastCommandType = RecivedPacket.commando;
			Server_Recived_Bytes_Len = RecivedPacket.recivedoffset;
			switch (RecivedPacket.commando) {
				case 2: //New Session
					if (SessionID === false) {
						SessionID = parseInt(RecivedPacket.data.toString());
					} else {
						console.error("Got a session id twice.");
					}
					break;
				case 3: //Empty response
					break;
				case 4: //There is more data on the server
				case 1: //Recived data from server
					DataFromServer_Arr[RecivedPacket.offset] = RecivedPacket.data;
					for (datOffset in DataFromServer_Arr) {
						if (NextByte_Len == datOffset) {
							NextByte_Len += DataFromServer_Arr[datOffset].length;
							process.stdout.write(DataFromServer_Arr[datOffset]);
							delete DataFromServer_Arr[datOffset];
						}
					}
					Time2NextRequest = options.timing

					break;
				case 5: //Server error
					console.error("Server reported error: " + RecivedPacket.data.toString());
					process.exit();
					break;
				default:
					console.error("Unknown commando: " + RecivedPacket.commando);
					process.exit();
					break;
			}
		}
		if (LastCommandType == 4) {
			//There is more Bytes on server, do new query
			MainLoop();
		}
	});
	req.send();
}
