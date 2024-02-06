// Copyright Epic Games, Inc. All Rights Reserved.

//-- Server side logic. Serves pixel streaming WebRTC-based page, proxies data back to Streamer --//

var express = require('express');
var app = express();
var Path = require('path');
								
const fs = require('fs');
const path = require('path');
const querystring = require('querystring');
const bodyParser = require('body-parser');
const logging = require('./modules/logging.js');
const cors = require('cors');
logging.RegisterConsoleLogger();

// Command line argument --configFile needs to be checked before loading the config, all other command line arguments are dealt with through the config object

var defaultConfig = {
	UseFrontend: false,
	UseMatchmaker: false,
	UseHTTPS: false,
	UseAuthentication: false,
	LogToFile: true,
	LogVerbose: true,
	HomepageFile: 'player.html',
	AdditionalRoutes: new Map(),
	EnableWebserver: true,
	MatchmakerAddress: "",
	MatchmakerPort: "9999",
	PublicIp: "localhost",
	HttpPort: 80,
	HttpsPort: 443,
	StreamerPort: 8888,
	SFUPort: 8889,
	MaxPlayerCount: -1
};

  defaultConfig = 
  {

	"UseFrontend": false,
	"UseMatchmaker": true,
	"UseHTTPS": true,
	"UseAuthentication": false,
	"LogToFile": true,
	"HomepageFile": "player.html",
	"AdditionalRoutes": {},
	"EnableWebserver": true,
	"MatchmakerAddress": "mps3.eaglepixelstreaming.com",
	"MatchmakerPort": "80",
	"MatchmakerHttpsPort": "443",
	"PublicIp": "xxx.60.91.140",
	"HttpPort": 80,
	"HttpsPort": 443,
	"StreamerPort": 8888,
	"owner": "",
	"SFUPort": 8889,
	"app": "",
	"domain": "aldar-staging.eaglepixelstreaming.com",
	"APIendpoint": "https://files-api.eaglepixelstreaming.com/",
	"exeDirectory": "C:/0.apps_azure/"
}


const argv = require('yargs').argv;
var configFile = (typeof argv.configFile != 'undefined') ? argv.configFile.toString() : path.join(__dirname, 'config.json');
console.log(`configFile ${configFile}`);
const config = require('./modules/config.js').init(configFile, defaultConfig);

if (config.LogToFile) {
	logging.RegisterFileLogger('./logs');
}


config.PublicIp=config.domain

console.log("Config: " + JSON.stringify(config, null, '\t'));

var http = require('http').Server(app);

if (config.UseHTTPS) {
	//HTTPS certificate details
	const options = {
		key: fs.readFileSync(path.join(__dirname, './certificates/client-key.pem')),
		cert: fs.readFileSync(path.join(__dirname, './certificates/client-cert.pem'))
	};

	var https = require('https').Server(options, app);
}

//If not using authetication then just move on to the next function/middleware
var isAuthenticated = redirectUrl => function (req, res, next) { return next(); }

if (config.UseAuthentication && config.UseHTTPS) {
	var passport = require('passport');
	require('./modules/authentication').init(app);
	// Replace the isAuthenticated with the one setup on passport module
	isAuthenticated = passport.authenticationMiddleware ? passport.authenticationMiddleware : isAuthenticated
} else if (config.UseAuthentication && !config.UseHTTPS) {
	console.error('Trying to use authentication without using HTTPS, this is not allowed and so authentication will NOT be turned on, please turn on HTTPS to turn on authentication');
}

const helmet = require('helmet');
var hsts = require('hsts');
var net = require('net');

var FRONTEND_WEBSERVER = 'https://localhost';
if (config.UseFrontend) {
	var httpPort = 3000;
	var httpsPort = 8000;

	//Required for self signed certs otherwise just get an error back when sending request to frontend see https://stackoverflow.com/a/35633993
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

	const httpsClient = require('./modules/httpsClient.js');
	var webRequest = new httpsClient();
} else {
	var httpPort = config.HttpPort;
	var httpsPort = config.HttpsPort;
}

var streamerPort = config.StreamerPort; // port to listen to Streamer connections
var sfuPort = config.SFUPort;

var matchmakerAddress = '127.0.0.1';
var matchmakerPort = 9999;
var matchmakerRetryInterval = 5;
var matchmakerKeepAliveInterval = 30;
var maxPlayerCount = -1;

var gameSessionId;
var userSessionId;
var serverPublicIp;

// `clientConfig` is send to Streamer and Players
// Example of STUN server setting
// let clientConfig = {peerConnectionOptions: { 'iceServers': [{'urls': ['stun:34.250.222.95:19302']}] }};
var clientConfig = { type: 'config', peerConnectionOptions: {} };

clientConfig.peerConnectionOptions=config.TurnCredentials;


// Parse public server address from command line
// --publicIp <public address>
try {
	if (typeof config.PublicIp != 'undefined') {
		serverPublicIp = config.PublicIp.toString();
	}

	if (typeof config.HttpPort != 'undefined') {
		httpPort = config.HttpPort;
	}

	if (typeof config.HttpsPort != 'undefined') {
		httpsPort = config.HttpsPort;
	}

	if (typeof config.StreamerPort != 'undefined') {
		streamerPort = config.StreamerPort;
	}

	if (typeof config.SFUPort != 'undefined') {
		sfuPort = config.SFUPort;
	}

	if (typeof config.FrontendUrl != 'undefined') {
		FRONTEND_WEBSERVER = config.FrontendUrl;
	}

	if (typeof config.peerConnectionOptions != 'undefined') {
		clientConfig.peerConnectionOptions = JSON.parse(config.peerConnectionOptions);
		console.log(`peerConnectionOptions = ${JSON.stringify(clientConfig.peerConnectionOptions)}`);
	} else {
		console.log("No peerConnectionConfig")
	}

	if (typeof config.MatchmakerAddress != 'undefined') {
		matchmakerAddress = config.MatchmakerAddress;
	}

	if (typeof config.MatchmakerPort != 'undefined') {
		matchmakerPort = config.MatchmakerPort;
	}

	if (typeof config.MatchmakerRetryInterval != 'undefined') {
		matchmakerRetryInterval = config.MatchmakerRetryInterval;
	}

	if (typeof config.MaxPlayerCount != 'undefined') {
		maxPlayerCount = config.MaxPlayerCount;
	}
} catch (e) {
	console.error(e);
	process.exit(2);
}

if (config.UseHTTPS) {
	app.use(helmet());

	app.use(hsts({
		maxAge: 15552000  // 180 days in seconds
	}));

	//Setup http -> https redirect
	console.log('Redirecting http->https');
	app.use(function (req, res, next) {
		if (!req.secure) {
			if (req.get('Host')) {
				var hostAddressParts = req.get('Host').split(':');
				var hostAddress = hostAddressParts[0];
				if (httpsPort != 443) {
					hostAddress = `${hostAddress}:${httpsPort}`;
				}
				return res.redirect(['https://', hostAddress, req.originalUrl].join(''));
			} else {
				console.error(`unable to get host name from header. Requestor ${req.ip}, url path: '${req.originalUrl}', available headers ${JSON.stringify(req.headers)}`);
				return res.status(400).send('Bad Request');
			}
		}
		next();
	});
}

sendGameSessionData();

//Setup the login page if we are using authentication
if(config.UseAuthentication){
	if(config.EnableWebserver) {
		app.get('/login', function(req, res){
			res.sendFile(__dirname + '/login.htm');
		});
	}

	// create application/x-www-form-urlencoded parser
	var urlencodedParser = bodyParser.urlencoded({ extended: false })

	//login page form data is posted here
	app.post('/login', 
		urlencodedParser, 
		passport.authenticate('local', { failureRedirect: '/login' }), 
		function(req, res){
			//On success try to redirect to the page that they originally tired to get to, default to '/' if no redirect was found
			var redirectTo = req.session.redirectTo ? req.session.redirectTo : '/';
			delete req.session.redirectTo;
			console.log(`Redirecting to: '${redirectTo}'`);
			res.redirect(redirectTo);
		}
	);
}

if(config.EnableWebserver) {
	//Setup folders
	app.use(express.static(path.join(__dirname, '/Public')))
	app.use('/images', express.static(path.join(__dirname, './images')))
	app.use('/scripts', [isAuthenticated('/login'),express.static(path.join(__dirname, '/scripts'))]);
	app.use('/', [isAuthenticated('/login'), express.static(path.join(__dirname, '/custom_html'))])
}

try {
	for (var property in config.AdditionalRoutes) {
		if (config.AdditionalRoutes.hasOwnProperty(property)) {
			console.log(`Adding additional routes "${property}" -> "${config.AdditionalRoutes[property]}"`)
			app.use(property, [isAuthenticated('/login'), express.static(path.join(__dirname, config.AdditionalRoutes[property]))]);
		}
	}
} catch (err) {
	console.error(`reading config.AdditionalRoutes: ${err}`)
}

if(config.EnableWebserver) {

	// Request has been sent to site root, send the homepage file
	app.get('/', isAuthenticated('/login'), function (req, res) {
		homepageFile = (typeof config.HomepageFile != 'undefined' && config.HomepageFile != '') ? config.HomepageFile.toString() : defaultConfig.HomepageFile;
		
		let pathsToTry = [ path.join(__dirname, homepageFile), path.join(__dirname, '/Public', homepageFile), path.join(__dirname, '/custom_html', homepageFile), homepageFile ];

		// Try a few paths, see if any resolve to a homepage file the user has set
		for(let pathToTry of pathsToTry){
			if(fs.existsSync(pathToTry)){
				// Send the file for browser to display it
				res.sendFile(pathToTry);
				return;
			}
		}

		// Catch file doesn't exist, and send back 404 if not
		console.error('Unable to locate file ' + homepageFile)
		res.status(404).send('Unable to locate file ' + homepageFile);
		return;
	});
}
//https://aldar-staging.eaglepixelstreaming.com:4431/getServerDetails
app.get('/getServerDetails', function (req, res) {
    config.numberofPlayers = players.size
    res.send(JSON.stringify(config))
    
    
  });
  
app.get('/kickAllUsersFromSS', function (req, res) {
		
		kickAllUsers(res)
		
	});
	
//Setup http and https servers
http.listen(httpPort, function () {
	console.logColor(logging.Green, 'Http listening on *: ' + httpPort);
});

if (config.UseHTTPS) {
	https.listen(httpsPort, function () {
		console.logColor(logging.Green, 'Https listening on *: ' + httpsPort);
	});
}

console.logColor(logging.Cyan, `Running Cirrus - The Pixel Streaming reference implementation signalling server for Unreal Engine 5.1.`);

let nextPlayerId = 100; // reserve some player ids
const SFUPlayerId = "1"; // sfu is a special kind of player

let streamer = null;				// WebSocket connected to Streamer
let sfu = null;					// WebSocket connected to SFU
let players = new Map(); 	// playerId <-> player, where player is either a web-browser or a native webrtc player

function sfuIsConnected() {
	return sfu && sfu.readyState == 1;
}

function logIncoming(sourceName, msgType, msg) {
	if (config.LogVerbose)
		console.logColor(logging.Blue, "\x1b[37m-> %s\x1b[34m: %s", sourceName, msg);
	else
		console.logColor(logging.Blue, "\x1b[37m-> %s\x1b[34m: %s", sourceName, msgType);
}

function logOutgoing(destName, msgType, msg) {
	if (config.LogVerbose)
		console.logColor(logging.Green, "\x1b[37m<- %s\x1b[32m: %s", destName, msg);
	else
		console.logColor(logging.Green, "\x1b[37m<- %s\x1b[32m: %s", destName, msgType);
}

// normal peer to peer signalling goes to streamer. SFU streaming signalling goes to the sfu
function sendMessageToController(msg, skipSFU, skipStreamer = false) {
	const rawMsg = JSON.stringify(msg);
	if (sfu && sfu.readyState == 1 && !skipSFU) {
		logOutgoing("SFU", msg.type, rawMsg);
		sfu.send(rawMsg);
	} 
	if (streamer && streamer.readyState == 1 && !skipStreamer) {
		logOutgoing("Streamer", msg.type, rawMsg);
		streamer.send(rawMsg);
	} 
	
	if (!sfu && !streamer) {
		console.error("sendMessageToController: No streamer or SFU connected!\nMSG: %s", rawMsg);
	}
}

function sendMessageToPlayer(playerId, msg) {
	let player = players.get(playerId);
	if (!player) {
		console.log(`dropped message ${msg.type} as the player ${playerId} is not found`);
		return;
	}
	const playerName = playerId == SFUPlayerId ? "SFU" : `player ${playerId}`;
	const rawMsg = JSON.stringify(msg);
	logOutgoing(playerName, msg.type, rawMsg);
	player.ws.send(rawMsg);
}

let WebSocket = require('ws');
const { URL } = require('url');

console.logColor(logging.Green, `WebSocket listening for Streamer connections on :${streamerPort}`)
let streamerServer = new WebSocket.Server({ port: streamerPort, backlog: 1 });
streamerServer.on('connection', function (ws, req) {

	// Check if we have an already existing connection to a streamer, if so, deny a new streamer connecting.
	if(streamer != null){
		/* We send a 1008 because that a "policy violation", which similar enough to what is happening here. */
		ws.close(1008, 'Cirrus supports only 1 streamer being connected, already one connected, so dropping this new connection.');
		console.logColor(logging.Yellow, `Dropping new streamer connection, we already have a connected streamer`);
		return;
	}

	console.logColor(logging.Green, `Streamer connected: ${req.connection.remoteAddress}`);
	sendStreamerConnectedToMatchmaker();

	ws.on('message', (msgRaw) => {

		var msg;
		try {
			msg = JSON.parse(msgRaw);
		} catch(err) {
			console.error(`cannot parse Streamer message: ${msgRaw}\nError: ${err}`);
			streamer.close(1008, 'Cannot parse');
			return;
		}

		logIncoming("Streamer", msg.type, msgRaw);
	
		try {
			// just send pings back to sender
			if (msg.type == 'ping') {
				const rawMsg = JSON.stringify({ type: "pong", time: msg.time});
				logOutgoing("Streamer", msg.type, rawMsg);
				ws.send(rawMsg);
				return;
			}

			// Convert incoming playerId to a string if it is an integer, if needed. (We support receiving it as an int or string).
			let playerId = msg.playerId;
			if (playerId && typeof playerId === 'number')
			{
				playerId = playerId.toString();
			}
			delete msg.playerId; // no need to send it to the player

			if (msg.type == 'offer') {
				sendMessageToPlayer(playerId, msg);
			} else if (msg.type == 'answer') {
				sendMessageToPlayer(playerId, msg);
			} else if (msg.type == 'iceCandidate') {
				sendMessageToPlayer(playerId, msg);
			} else if (msg.type == 'disconnectPlayer') {
				let player = players.get(playerId);
				if (player) {
					player.ws.close(1011 /* internal error */, msg.reason);
				}
			} else {
				console.error(`unsupported Streamer message type: ${msg.type}`);
			}
		} catch(err) {
			console.error(`ERROR: ws.on message error: ${err.message}`);
		}
	});

	function onStreamerDisconnected() {
		sendStreamerDisconnectedToMatchmaker();
		disconnectAllPlayers();
		if (sfuIsConnected()) {
			const msg = { type: "streamerDisconnected" };
			sfu.send(JSON.stringify(msg));
		}
		streamer = null;
	}
	
	ws.on('close', function(code, reason) {
		console.error(`streamer disconnected: ${code} - ${reason}`);
		onStreamerDisconnected();
	});

	ws.on('error', function(error) {
		console.error(`streamer connection error: ${error}`);
		onStreamerDisconnected();
		try {
			ws.close(1006 /* abnormal closure */, error);
		} catch(err) {
			console.error(`ERROR: ws.on error: ${err.message}`);
		}
	});

	streamer = ws;

	streamer.send(JSON.stringify(clientConfig));

	if (sfuIsConnected()) {
		const msg = { type: "playerConnected", playerId: SFUPlayerId, dataChannel: true, sfu: true };
		streamer.send(JSON.stringify(msg));
	}
});

console.logColor(logging.Green, `WebSocket listening for SFU connections on :${sfuPort}`);
let sfuServer = new WebSocket.Server({ port: sfuPort});
sfuServer.on('connection', function (ws, req) {
	// reject if we already have an sfu
	if (sfuIsConnected()) {
		ws.close(1013, 'Already have SFU');
		return;
	}

	players.set(SFUPlayerId, { ws: ws, id: SFUPlayerId });

	ws.on('message', (msgRaw) => {
		var msg;
		try {
			msg = JSON.parse(msgRaw);
		} catch (err) {
			console.error(`cannot parse SFU message: ${msgRaw}\nError: ${err}`);
			ws.close(1008, 'Cannot parse');
			return;
		}

		logIncoming("SFU", msg.type, msgRaw);

		if (msg.type == 'offer') {
			// offers from the sfu are for players
			const playerId = msg.playerId;
			delete msg.playerId;
			sendMessageToPlayer(playerId, msg);
		}
		else if (msg.type == 'answer') {
			// answers from the sfu are for the streamer
			msg.playerId = SFUPlayerId;
			const rawMsg = JSON.stringify(msg);
			logOutgoing("Streamer", msg.type, rawMsg);
			streamer.send(rawMsg);
		}
		else if (msg.type == 'streamerDataChannels') {
			// sfu is asking streamer to open a data channel for a connected peer
			msg.sfuId = SFUPlayerId;
			const rawMsg = JSON.stringify(msg);
			logOutgoing("Streamer", msg.type, rawMsg);
			streamer.send(rawMsg);
		}
		else if (msg.type == 'peerDataChannels') {
			// sfu is telling a peer what stream id to use for a data channel
			const playerId = msg.playerId;
			delete msg.playerId;
			sendMessageToPlayer(playerId, msg);
			// remember the player has a data channel
			const player = players.get(playerId);
			player.datachannel = true;
		}
	});

	ws.on('close', function(code, reason) {
		console.error(`SFU disconnected: ${code} - ${reason}`);
		sfu = null;
		disconnectSFUPlayer();
	});

	ws.on('error', function(error) {
		console.error(`SFU connection error: ${error}`);
		sfu = null;
		disconnectSFUPlayer();
		try {
			ws.close(1006 /* abnormal closure */, error);
		} catch(err) {
			console.error(`ERROR: ws.on error: ${err.message}`);
		}
	});

	sfu = ws;
	console.logColor(logging.Green, `SFU (${req.connection.remoteAddress}) connected `);

	if (streamer && streamer.readyState == 1) {
		const msg = { type: "playerConnected", playerId: SFUPlayerId, dataChannel: true, sfu: true };
		streamer.send(JSON.stringify(msg));
	}
});

let playerCount = 0;

console.logColor(logging.Green, `WebSocket listening for Players connections on :${httpPort}`);
let playerServer = new WebSocket.Server({ server: config.UseHTTPS ? https : http});
playerServer.on('connection', function (ws, req) {
	// Reject connection if streamer is not connected
	if (!streamer || streamer.readyState != 1 /* OPEN */) {
		ws.close(1013 /* Try again later */, 'Streamer is not connected');
		return;
	}
	console.logColor(logging.Blue, `players.size: ${players.size}`);
	if( players && players.size >= 1) 
		{
			var message="Intrueder detected while players.size"+players.size
			//postToTelegram(message) 
			console.logColor(logging.Red, message);

			ws.close(1013 /* Try again later */, 'Server already occupied');
			return 
		}
		

	var url = require('url');
	const parsedUrl = url.parse(req.url);
	const urlParams = new URLSearchParams(parsedUrl.search);
	const preferSFU = urlParams.has('preferSFU') && urlParams.get('preferSFU') !== 'false';
	const skipSFU = !preferSFU;
	const skipStreamer = preferSFU && sfu;

	if(preferSFU && !sfu) {
		ws.send(JSON.stringify({ type: "warning", warning: "Even though ?preferSFU was specified, there is currently no SFU connected." }));
	}

	if(playerCount + 1 > maxPlayerCount && maxPlayerCount !== -1)
	{
		console.logColor(logging.Red, `new connection would exceed number of allowed concurrent connections. Max: ${maxPlayerCount}, Current ${playerCount}`);
		ws.close(1013, `too many connections. max: ${maxPlayerCount}, current: ${playerCount}`);
		return;
	}

	++playerCount;
	let playerId = (++nextPlayerId).toString();
	console.logColor(logging.Green, `player ${playerId} (${req.connection.remoteAddress}) connected`);
	players.set(playerId, { ws: ws, id: playerId });

	function sendPlayersCount() {
		let playerCountMsg = JSON.stringify({ type: 'playerCount', count: players.size });
		for (let p of players.values()) {
			p.ws.send(playerCountMsg);
		}
	}
	
	ws.on('message', (msgRaw) =>{

		var msg;
		try {
			msg = JSON.parse(msgRaw);
		} catch (err) {
			console.error(`cannot parse player ${playerId} message: ${msgRaw}\nError: ${err}`);
			ws.close(1008, 'Cannot parse');
			return;
		}

		if(!msg || !msg.type)
		{
			console.error(`Cannot parse message ${msgRaw}`);
			return;
		}
		
		logIncoming(`player ${playerId}`, msg.type, msgRaw);

		if (msg.type == 'offer') {
			msg.playerId = playerId;
			sendMessageToController(msg, skipSFU);
		} else if (msg.type == 'answer') {
			msg.playerId = playerId;
			sendMessageToController(msg, skipSFU, skipStreamer);
		} else if (msg.type == 'iceCandidate') {
			msg.playerId = playerId;
			sendMessageToController(msg, skipSFU, skipStreamer);
		} else if (msg.type == 'stats') {
			console.log(`player ${playerId}: stats\n${msg.data}`);
		} else if (msg.type == "dataChannelRequest") {
			msg.playerId = playerId;
			sendMessageToController(msg, skipSFU, true);
		} else if (msg.type == "peerDataChannelsReady") {
			msg.playerId = playerId;
			sendMessageToController(msg, skipSFU, true);
		}
		else {
			console.error(`player ${playerId}: unsupported message type: ${msg.type}`);
			return;
		}
	});

	function onPlayerDisconnected() {
		try {
			--playerCount;
			const player = players.get(playerId);
			if (player.datachannel) {
				// have to notify the streamer that the datachannel can be closed
				sendMessageToController({ type: 'playerDisconnected', playerId: playerId }, true, false);
			}
			players.delete(playerId);
			sendMessageToController({ type: 'playerDisconnected', playerId: playerId }, skipSFU);
			sendPlayerDisconnectedToFrontend();
			sendPlayerDisconnectedToMatchmaker();
			sendPlayersCount();
		} catch(err) {
			console.logColor(logging.Red, `ERROR:: onPlayerDisconnected error: ${err.message}`);
		}
		
		if( !players || players.size <= 0) 
		{
			 //restartApp() 
			 restartUnrealApp()
		}
		
	}

	ws.on('close', function(code, reason) {
		console.logColor(logging.Yellow, `player ${playerId} connection closed: ${code} - ${reason}`);
		onPlayerDisconnected();
		
		//setTimeout(stoptUnrealApp, 500);
		
	});

	ws.on('error', function(error) {
		console.error(`player ${playerId} connection error: ${error}`);
		ws.close(1006 /* abnormal closure */, error);
		onPlayerDisconnected();

		console.logColor(logging.Red, `Trying to reconnect...`);
		reconnect();
	});

	sendPlayerConnectedToFrontend();
	sendPlayerConnectedToMatchmaker();

	ws.send(JSON.stringify(clientConfig));

	sendMessageToController({ type: "playerConnected", playerId: playerId, dataChannel: true, sfu: false }, skipSFU, skipStreamer);
	sendPlayersCount();
});

function disconnectAllPlayers(code, reason) {
	console.log("killing all players");
	let clone = new Map(players);
	for (let player of clone.values()) {
		if (player.id != SFUPlayerId) { // dont dc the sfu
			player.ws.close(code, reason);
		}
	}
}

function disconnectSFUPlayer() {
	console.log("disconnecting SFU from streamer");
	if(players.has(SFUPlayerId)) {
		players.get(SFUPlayerId).ws.close(4000, "SFU Disconnected");
		players.delete(SFUPlayerId);
	}
	sendMessageToController({ type: 'playerDisconnected', playerId: SFUPlayerId }, true, false);
}

/**
 * Function that handles the connection to the matchmaker.
 */


function kickAllUsers(res) 
{
		let playersCopy = new Map(players);
			for (let p of playersCopy.values()) 
			{
				
					console.log(`kicking player ${p.id}`)
					p.ws.close(4000, 'kicked');
				
			}
			console.logColor(logging.Red, 'kicked cmd executed ' );

			if(res)
				res.send("kicked cmd executed")
			
			
}
	
	
	
if (config.UseMatchmaker) {
	var matchmaker = new net.Socket();

matchmaker.on('data', (data) => {

try {
			message = JSON.parse(data);

			if(message)
				console.log(`Message TYPE: ${message.type}`);
		}
		catch(e) 
		{
			console.log(data);
			console.log(data.toString());
			console.log(`ERROR (${e.toString()}): Failed to parse matchmaker information from data: ${data.toString()}`);
			disconnectAllPlayers();
			return;
		}
		
		var sfsf='mm-->ss: ' + JSON.stringify(message)
		
		if (message.type === 'kickAllUsers') 
		{
			kickAllUsers()
			
			
		}
			
}
)


	matchmaker.on('connect', function() {
		console.log(`Cirrus connected to Matchmaker ${matchmakerAddress}:${matchmakerPort}`);

		// message.playerConnected is a new variable sent from the SS to help track whether or not a player 
		// is already connected when a 'connect' message is sent (i.e., reconnect). This happens when the MM
		// and the SS get disconnected unexpectedly (was happening often at scale for some reason).
		var playerConnected = false;

		// Set the playerConnected flag to tell the MM if there is already a player active (i.e., don't send a new one here)
		if( players && players.size > 0) {
			playerConnected = true;
		}

		// Add the new playerConnected flag to the message body to the MM
		message = {
			type: 'connect',
			address: typeof serverPublicIp === 'undefined' ? '127.0.0.1' : serverPublicIp,
			port: httpPort,
			HttpsPort: config.HttpsPort,
			domain: config.domain,
			ready: streamer && streamer.readyState === 1,
			playerConnected: playerConnected
		};
			var message=JSON.stringify(message)
		//postToTelegram(message) 
		
		console.log("ss-Mmm: "+message);
		matchmaker.write(message);
	});

	matchmaker.on('error', (err) => {
		var message=`Matchmaker connection error ${JSON.stringify(err)}`
		//postToTelegram(message) 
		
		console.log(message);
	});

	matchmaker.on('end', () => {
		
		
		var message='Matchmaker connection ended'
		//postToTelegram(message) 
		
		console.log(message);
	});

	matchmaker.on('close', (hadError) => {
		console.logColor(logging.Blue, 'Setting Keep Alive to true');
        matchmaker.setKeepAlive(true, 60000); // Keeps it alive for 60 seconds
		
		

		var message=`Matchmaker connection closed (hadError=${hadError})`
		//postToTelegram(message) 
		
		console.log(message);
		
		reconnect();
	});

	// Attempt to connect to the Matchmaker
	function connect() {
		matchmaker.connect(matchmakerPort, matchmakerAddress);
	}

	// Try to reconnect to the Matchmaker after a given period of time
	function reconnect() {
		console.log(`Try reconnect to Matchmaker in ${matchmakerRetryInterval} seconds`)
		setTimeout(function() {
			connect();
		}, matchmakerRetryInterval * 1000);
	}

	function registerMMKeepAlive() {
		setInterval(function() {
			message = {
				type: 'ping'
			};
			matchmaker.write(JSON.stringify(message));
		}, matchmakerKeepAliveInterval * 1000);
	}

	connect();
	registerMMKeepAlive();
}

//Keep trying to send gameSessionId in case the server isn't ready yet
function sendGameSessionData() {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	webRequest.get(`${FRONTEND_WEBSERVER}/server/requestSessionId`,
		function (response, body) {
			if (response.statusCode === 200) {
				gameSessionId = body;
				console.log('SessionId: ' + gameSessionId);
			}
			else {
				console.error('Status code: ' + response.statusCode);
				console.error(body);
			}
		},
		function (err) {
			//Repeatedly try in cases where the connection timed out or never connected
			if (err.code === "ECONNRESET") {
				//timeout
				sendGameSessionData();
			} else if (err.code === 'ECONNREFUSED') {
				console.error('Frontend server not running, unable to setup game session');
			} else {
				console.error(err);
			}
		});
}

function sendUserSessionData(serverPort) {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	webRequest.get(`${FRONTEND_WEBSERVER}/server/requestUserSessionId?gameSessionId=${gameSessionId}&serverPort=${serverPort}&appName=${querystring.escape(clientConfig.AppName)}&appDescription=${querystring.escape(clientConfig.AppDescription)}${(typeof serverPublicIp === 'undefined' ? '' : '&serverHost=' + serverPublicIp)}`,
		function (response, body) {
			if (response.statusCode === 410) {
				sendUserSessionData(serverPort);
			} else if (response.statusCode === 200) {
				userSessionId = body;
				console.log('UserSessionId: ' + userSessionId);
			} else {
				console.error('Status code: ' + response.statusCode);
				console.error(body);
			}
		},
		function (err) {
			//Repeatedly try in cases where the connection timed out or never connected
			if (err.code === "ECONNRESET") {
				//timeout
				sendUserSessionData(serverPort);
			} else if (err.code === 'ECONNREFUSED') {
				console.error('Frontend server not running, unable to setup user session');
			} else {
				console.error(err);
			}
		});
}

function sendServerDisconnect() {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	try {
		webRequest.get(`${FRONTEND_WEBSERVER}/server/serverDisconnected?gameSessionId=${gameSessionId}&appName=${querystring.escape(clientConfig.AppName)}`,
			function (response, body) {
				if (response.statusCode === 200) {
					console.log('serverDisconnected acknowledged by Frontend');
				} else {
					console.error('Status code: ' + response.statusCode);
					console.error(body);
				}
			},
			function (err) {
				//Repeatedly try in cases where the connection timed out or never connected
				if (err.code === "ECONNRESET") {
					//timeout
					sendServerDisconnect();
				} else if (err.code === 'ECONNREFUSED') {
					console.error('Frontend server not running, unable to setup user session');
				} else {
					console.error(err);
				}
			});
	} catch(err) {
		console.logColor(logging.Red, `ERROR::: sendServerDisconnect error: ${err.message}`);
	}
}

function sendPlayerConnectedToFrontend() {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	try {
		webRequest.get(`${FRONTEND_WEBSERVER}/server/clientConnected?gameSessionId=${gameSessionId}&appName=${querystring.escape(clientConfig.AppName)}`,
			function (response, body) {
				if (response.statusCode === 200) {
					console.log('clientConnected acknowledged by Frontend');
				} else {
					console.error('Status code: ' + response.statusCode);
					console.error(body);
				}
			},
			function (err) {
				//Repeatedly try in cases where the connection timed out or never connected
				if (err.code === "ECONNRESET") {
					//timeout
					sendPlayerConnectedToFrontend();
				} else if (err.code === 'ECONNREFUSED') {
					console.error('Frontend server not running, unable to setup game session');
				} else {
					console.error(err);
				}
			});
	} catch(err) {
		console.logColor(logging.Red, `ERROR::: sendPlayerConnectedToFrontend error: ${err.message}`);
	}
}

function sendPlayerDisconnectedToFrontend() {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	try {
		webRequest.get(`${FRONTEND_WEBSERVER}/server/clientDisconnected?gameSessionId=${gameSessionId}&appName=${querystring.escape(clientConfig.AppName)}`,
			function (response, body) {
				if (response.statusCode === 200) {
					console.log('clientDisconnected acknowledged by Frontend');
				}
				else {
					console.error('Status code: ' + response.statusCode);
					console.error(body);
				}
			},
			function (err) {
				//Repeatedly try in cases where the connection timed out or never connected
				if (err.code === "ECONNRESET") {
					//timeout
					sendPlayerDisconnectedToFrontend();
				} else if (err.code === 'ECONNREFUSED') {
					console.error('Frontend server not running, unable to setup game session');
				} else {
					console.error(err);
				}
			});
	} catch(err) {
		console.logColor(logging.Red, `ERROR::: sendPlayerDisconnectedToFrontend error: ${err.message}`);
	}
}

function sendStreamerConnectedToMatchmaker() {
	if (!config.UseMatchmaker)
		return;
	try {
		message = {
			type: 'streamerConnected'
		};
		matchmaker.write(JSON.stringify(message));
	} catch (err) {
		console.logColor(logging.Red, `ERROR sending streamerConnected: ${err.message}`);
	}
}

function sendStreamerDisconnectedToMatchmaker() {
	if (!config.UseMatchmaker)
	{
		return;
	}

	try {
		message = {
			type: 'streamerDisconnected'
		};
		matchmaker.write(JSON.stringify(message));	
	} catch (err) {
		console.logColor(logging.Red, `ERROR sending streamerDisconnected: ${err.message}`);
	}
}

// The Matchmaker will not re-direct clients to this Cirrus server if any client
// is connected.
function sendPlayerConnectedToMatchmaker() {
	if (!config.UseMatchmaker)
		return;
	try {
		message = {
			type: 'clientConnected',
			numplayer:players.size
		};
		matchmaker.write(JSON.stringify(message));
		console.logColor(logging.Red, "SS-->mm : "+JSON.stringify(message));
		
	} catch (err) {
		console.logColor(logging.Red, `ERROR sending clientConnected: ${err.message}`);
	}
}

// The Matchmaker is interested when nobody is connected to a Cirrus server
// because then it can re-direct clients to this re-cycled Cirrus server.
function sendPlayerDisconnectedToMatchmaker() {
	if (!config.UseMatchmaker)
		return;
	try {
		message = {
			type: 'clientDisconnected',
			numplayer:players.size
		};
		matchmaker.write(JSON.stringify(message));
		console.logColor(logging.Red, "SS-->mm : "+JSON.stringify(message));
	} catch (err) {
		console.logColor(logging.Red, `ERROR sending clientDisconnected: ${err.message}`);
	}
}

/////////////////////////Ahsan//////////////////////
const request = require('request')
var ue4Process=undefined
var currentVersion=-1
var exeDirectory=config.exeDirectory
var isupdateonProcess=false
var owner=config.owner//"ruya"
var app=config.app//"EagleStreamingMechns"
var axios = require("axios");
var AppDataProvidedBySS={
													owner:"",
													AppName:"",
													version:""
													
												}



function getAppDetails()
{
	
    const axiosConfig = {
      headers: {
        'Content-Type': 'application/json', 
        'Ocp-Apim-Subscription-Key': config.SubKey
      },
    };

    var url = config.APIendpoint + config.owner + "/" + config.app


    console.log("getAppDetails() url :" + url);

    let flag =
        axios.get(url, axiosConfig)
        .then(
            (result) =>
            {
                 //console.log("getAppDetails result.data : "+JSON.stringify(result.data) );
                // console.log("getAppDetails result.data : "+JSON.stringify(result.data.data) );
                // console.log("getAppDetails result.data : "+JSON.stringify(result.data.data.blobs) );
                //console.log("getAppDetails result.data : "+JSON.stringify(result.data.data.blobs) )

				if(result== undefined)
					return


                var array = result.data.data["blobs"];
                array = result.data.data["blobs"][0];
                //console.log(typeof array);
                //console.log("getAppDetails console : "+JSON.stringify(array) )

                //console.log("length  : "+result.data.data["blobs"].length );
                var maxVersion = -1
                var max = undefined
				if(result.data.data["blobs"].length<=0)
				{
					console.log("no uploaded file found " );
					return
				}
                for (var i = 0; i < result.data.data["blobs"].length; i++)
                {
                    var fsgsgsg = result.data.data["blobs"][i]
                    //console.log("fsgsgsg: "+JSON.stringify(fsgsgsg) );
                    var n = parseInt(Path.parse(fsgsgsg.filename).name)
                    if (maxVersion < n)
                    {
                        maxVersion = n
                        max = fsgsgsg
                    }

                }


                //console.log("getAppDetails max : "+JSON.stringify(max) );
                //console.log("getAppDetails max.url : " + max.url);



                var version = Path.parse(max.filename).name

                if (currentVersion != -1)
                {
                    if (version != currentVersion)
                    {
                        console.log("new version available currentVersion : " + currentVersion);
                        console.logColor(logging.Blue, "new version available version : " + version);
                    }

                }


				var oldversion=AppDataProvidedBySS.version
               // AppDataProvidedBySS.owner = owner,
                //    AppDataProvidedBySS.AppName = app,
                    AppDataProvidedBySS.version = version




                var dirname = Path.dirname(max.filename)



               

                //console.log("downloadFolder : "+downloadFolder );
                //console.log("version : "+version );
                //console.log("dirname : "+dirname );


                var ue4AppExe =
                    exeDirectory +
                    config.owner +
                    "\\" + config.app +
                    "\\" + AppDataProvidedBySS.version + "\\" + config.app + ".exe"

                if (fs.existsSync(ue4AppExe))
                {
                    if (!streamer || streamer.readyState != 1)
                        //restartApp() 	
                        StartUnrealApp("ue4")

                }
                else
                {
					 var downloadFolder = exeDirectory + dirname + "/temp_" + version + "/"
					 
								//postToTelegram("a new version detected: "+
								//oldversion
								//+" --> "
								//+AppDataProvidedBySS.version
								//) 
                    isupdateonProcess = true

                    ensureDirectoryExistence(downloadFolder + "dummyFile")

                    const downloadpath = downloadFolder + Path.basename(max.filename)
                    console.log("downloadpath : " + downloadpath);

                    downloadFile(max.url,
                        downloadpath,
                        downloadFolder, AppDataProvidedBySS
                    );



                }


                return result.data
            }
        )

        .catch((err) =>
        {
            console.log(
                "  err:" + err
            );
        });

    //console.log("flag : "+flag );		
}


function extractUsing7Zip(downloadFilePath, downloadFolder, AppDataProvidedBySS) //2do-downloadFilePath to downloadedFilePath
{
    var sevenzip = require('@steezcram/sevenzip');
    var n = AppDataProvidedBySS.version
    var tttt = downloadFolder
    var isAdminDebugging = true


    var lastprogressState = undefined;
    var shouldDoProgressUpdate = true
    if (isAdminDebugging)
    {
        shouldDoProgressUpdate = true
    }


    sevenzip.extract('7z',
        {
            archive: downloadFilePath,
            destination: downloadFolder
        },
        (err) =>
        {
            if (err)
                throw err;

            isupdateonProcess = false


            var dfsfgsf = JSON.stringify(err)

            console.log("SevenZipStream : error:" + dfsfgsf);



            console.log(err);




        },
        (progress) =>
        {
            console.log(progress);
            lastprogressState = progress;



            var obj = {
                type: "AppPreparationData",
                data:
                {
                    percent: progress.progress
                }
            }
            var dfsfgsf = JSON.stringify(obj)
            sendMessageToPlayers(dfsfgsf)

            console.log(dfsfgsf);

            if (progress.progress >= 100)
            {

                console.logColor(logging.Blue, "Extraction finished******************");

                if (lastprogressState && lastprogressState.percent < 90)
                {
                    console.log("SevenZipStream-->end: skipping lunch bcz. lastprogressState:--> " + JSON.stringify(lastprogressState))
                    //return;
                }



                var obj = {
                    datatype: "type",
                    data:

                    {


                        "percent": 100,
                        "ahsanMademessage": "SevenZipStream.onEnd"

                    }



                }
                var dfsfgsf = JSON.stringify(obj)
                sendMessageToPlayers(dfsfgsf)
                console.log("SevenZipStream : Extraction end");



                var ttttt2 = exeDirectory +
                    "\\" + config.owner + "\\" + config.app +
                    "\\" + AppDataProvidedBySS.version + "\\"

                messageToSend = 'starting rename   from: ' + tttt + 'to :' + ttttt2
                //var ttttt2=exeDirectory+"\\"+data.AppInfoRequested2Linker.owner+"\\"+ data.parentFolder+ "\\"+ path.parse(data.filename).name+ "\\"


                fs.rename(tttt, ttttt2, function(err)
                {
                    if (err)
                    {
                        console.log(err);

                        return; //2do--add all clean up  related code
                    }
                    else
                    {
                        messageToSend = 'SevenZipStream : 222renamed complete from: ' + tttt + 'to :' + ttttt2
                        console.logColor(logging.Blue, messageToSend);
                        //sendMesage2DownloadWaittingList(messageToSend,CompanyName,AppName,n)

                        var zipFIleTodetele = ttttt2 + AppDataProvidedBySS.version + ".zip"
                        onExePrepared(zipFIleTodetele, AppDataProvidedBySS)

                    }

                });




            }


        });

}


function ensureDirectoryExistence(filePath) 
{
	// console.log('ensureDirectoryExistence: ' +filePath );
									
  var dirname = path.dirname(filePath);
  if (fs.existsSync(dirname)) 
  {
    return true;
  }
  ensureDirectoryExistence(dirname);
  fs.mkdirSync(dirname);
}


function deleteFile(path) 
{

	if (path) 
	{
	  fs.access(path, 
	  // fs.constants.R_OK | fs.constants.W_OK
	  fs.R_OK && fs.W_OK
	  
	  , function(err) 
	  {
		   if (err) 
		   {
			 console.log("deleteFile() Cannot delete this folder:"+path)
			 console.log(err);
			 
			 setTimeout(function () 
												{	 
													deleteFile(path) 
																			
												}
													, 5000
											); 
											
		   } 
		   else 
		   {
					fs.unlink(path,function(err)
					{
						if(err)
						{
							if(err.code == 'ENOENT') 
							{
								// file doens't exist
								console.info("deleteFile() File doesn't exist, won't remove it.");
							} 
							else
							{
								
								
								setTimeout(function () 
												{	 
													deleteFile(path) 
																			
												}
													, 5000
											); 
																			
								
							}
							 
								console.log(err);
						 
						}
						else
						{
						
						console.log('deleteFile() file deleted successfully '+path);
						}
					});  
		   }
	  }
	  
	  
	  
	  
	  );
	}
 

}


			 
getAppDetails() 

setInterval(
			function() 
			{
				//console.log("xxxxxxxxxxxxxxxxx isupdateonProcess: "+isupdateonProcess);
				if(!isupdateonProcess)
					getAppDetails()
				else
					console.log("skipping getAppDetails bcz isupdateonProcess: "+isupdateonProcess);
			 }, 10 * 1000);



function onExePrepared(zipFIleTodetele,AppDataProvidedBySS)
{
	isupdateonProcess=false	
	deleteFile(zipFIleTodetele) 		
	restartUnrealApp() 
		
}


function sendMessageToPlayers(message)
{
	for (let p of players.values()) 
	{
			p.ws.send(message);
		}
}

			 
function downloadFile(file_url , targetPath,
									downloadFolder,AppDataProvidedBySS)
{
	isupdateonProcess=true
	
    // Save variable to know progress
    var received_bytes = 0;
    var total_bytes = 0;

    var req = request({
        method: 'GET',
        uri: file_url
    });

    var out = fs.createWriteStream(targetPath);
    req.pipe(out);

    req.on('response', function ( data ) {
        // Change the total bytes value to get progress later.
        total_bytes = parseInt(data.headers['content-length' ]);
    });

    req.on('data', function(chunk) {
        // Update the received bytes
        received_bytes += chunk.length;

        showProgress(received_bytes, total_bytes);
    });

    req.on('end', function() {
        console.log("File succesfully downloaded");
		
		 var obj={type:"AppAcquiringData",
						 data:{
														  
														  
								"percent": 100,
								"ahsanMademessage":"request-progressToDownload.onEnd"
														 
							}
						 
						 
						 }
						 var dfsfgsf=JSON.stringify(obj)
													 
						sendMessageToPlayers( dfsfgsf)	
						
						
		 setTimeout(		
		 function () //give downlapoder some time to save in disk
			{
																									
				extractUsing7Zip(targetPath,downloadFolder,AppDataProvidedBySS)
			}, 
			5000)
										
										
    });
}


function showProgress(received,total){
    var percentage = (received * 100) / total;
    console.log(percentage + "% | " + received + " bytes out of " + total + " bytes.");
    // 50% | 50000 bytes received out of 100000 bytes.
	
	
		 var obj={type:"AppAcquiringData",
						 data:{
														  
														  
								"percent": percentage,
								"ahsanMademessage":"request-progressToDownload.onEnd"
														 
							}
						 
						 
						 }
						 var dfsfgsf=JSON.stringify(obj)
													 
						sendMessageToPlayers( dfsfgsf)	
		
}


function restartUnrealApp() 
{
	stoptUnrealApp(true) 
}
function stoptUnrealApp(shouldRestart=false) 
{
	if (!streamer)
		{
			console.logColor(logging.Red,"stoptUnrealApp() streamer undefined. so no exe to stop.   " );
			console.logColor(logging.Red,"stoptUnrealApp() shouldRestart:   "+shouldRestart );
				if(shouldRestart)
					StartUnrealApp()
			return
		}
		
		
		// Call the restart PowerShell script only if all players have disconnected
		if(players.size == 0) 
		{
			try {
				var spawn = require("child_process").spawn,child;
				
				
				
				var cmd= ".\\StopApp.ps1 "
						+app+" "
						+ config.StreamerPort+" "
						+0 
						
						
				console.logColor(logging.Blue,"stoptUnrealApp() cmd : "+cmd );
				child = spawn("powershell.exe",[cmd]);
				
				child.stdout.on("data", function(data) {
					console.log("stoptUnrealApp PowerShell Data: " + data);
					
					if(data== "Process killed")
					{
									if (streamer)
									{
										console.logColor(logging.Blue,"stoptUnrealApp() Process killed. yes. streamer killed " );
										
										
									}
									else
										console.logColor(logging.Blue,"stoptUnrealApp() Process killed. . streamer stilol running  " );
					}
				});
				child.stderr.on("data", function(data) {
					console.log("stoptUnrealApp PowerShell Errors: " + data);
				});
				child.on("exit",function(){
					console.log("stoptUnrealApp The PowerShell script complete.");
					if(shouldRestart)
						StartUnrealApp()
				});
				child.stdin.end();
			} catch(e) {
				console.log(`stoptUnrealApp ERROR: Errors executing PowerShell with message: ${e.toString()}`);
				ai.logError(e);	//////// AZURE ////////
			}
		}
}

var isLunchingStramer=false
function StartUnrealApp() 
{
		if (streamer)
		{
			console.logColor(logging.Red,"StartUnrealApp() but stramer connected. excuting restartUnrealApp()  " );
			restartUnrealApp()
			return
		}
		console.logColor(logging.Red,"StartUnrealApp() isLunchingStramer:  "+isLunchingStramer );
		if(isLunchingStramer)
			return
		
		console.trace()
			try 
			{
				isLunchingStramer=true
				var spawn = require("child_process").spawn,child;
				// TODO: Need to pass in a config path to this for more robustness and not hard coded
				
		
				var pathtoexec	=  
						exeDirectory 
						+config.owner
						+"\\"+config.app
						+"\\"
						+AppDataProvidedBySS.version+"\\"+config.app+".exe" 
									
					console.log('33333333333  pathtoexec: ' + pathtoexec);
					
					if (fs.existsSync(pathtoexec))
						{
											
						}
						else
						{
							console.logColor(logging.Red,"StartUnrealApp() exe dont exist:  "+pathtoexec );
							isLunchingStramer=false
							return					
						}
						
					var cmd= 
						".\\StartApp.ps1 "
						+pathtoexec+" "
						+ config.StreamerPort
						
					console.log(cmd);	
				
				
				
				child = spawn("powershell.exe",[cmd]);
				
				child.stdout.on("data", function(data) {
					//console.log("PowerShell Data: " + data);
				});
				child.stderr.on("data", function(data) {
					//console.log("PowerShell Errors: " + data);
				});
				child.on("exit",function(){
					//isLunchingStramer=false
					console.log("StartUnrealApp The PowerShell script complete.");
				});
				child.stdin.end();
				
				ue4Process=child
				
			} catch(e) {
				console.log(`StartUnrealApp ERROR: Errors executing PowerShell with message: ${e.toString()}`);
				ai.logError(e);	//////// AZURE ////////
			}
		
}

//https://stackoverflow.com/questions/31673587/error-unable-to-verify-the-first-certificate-in-nodejs
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0
function checkStatusInMM()
{
//https://mmkr-snbx.jllmena.me/getAllCS
//https://mps3.eaglepixelstreaming.com/getAllCS
//https://aldar-staging.eaglepixelstreaming.com:4430/getAllCS
//http://aldar-staging.eaglepixelstreaming.com:33891/getAllCS
    var url = "https://"+config.MatchmakerAddress+":"+config.MatchmakerHttpsPort + "/getAllCS"
    //https://files-api.eaglepixelstreaming.com/api/v1/files/ruya/EagleStreamingMechns/


    console.log("checkStatusInMM() url :" + url);



// var https2 = require('https');
// var rootCas = require('ssl-root-cas').create();

// rootCas.addFile(path.join(__dirname, './certificates/client-key.pem'));
// var httpsAgent2 = new https2.Agent({ca: rootCas});

// const httpsAgent2 = new require("https").Agent({
  // rejectUnauthorized: true,
// });
  
  
    let flag =
        axios.get(
		url 
		//	, { httpsAgent2 }
		)
        .then(
            (result) =>
            {
                // console.log("getAppDetails result.data : "+JSON.stringify(result) );
                 //console.log("getAppDetails result.data : "+JSON.stringify(result.data) );
                
				
for(i=0;i<result.data.length;i++)
{
	/* console.log(result.data[i].domain);
	console.log(config.domain);
	
		console.log(result.data[i].port);
	console.log(config.HttpPort);
		console.log(result.data[i].HttpsPort);
	console.log(config.HttpsPort); */
	
	if(
	(result.data[i].domain==config.domain)
	&&(result.data[i].port==config.HttpPort)
	&&(result.data[i].HttpsPort==config.HttpsPort)
	)
	{
		console.log("found" );
		
		if(result.data[i].numConnectedClients != players.size)
		{
			console.logColor(logging.Red, "result.data[i].numConnectedClients : "+result.data[i].numConnectedClients);
			console.logColor(logging.Red, "players.size : "+players.size);
		}
		
		break
	}
	
	
	
}


               
            }
        )

        .catch((err) =>
        {
            console.log(
                " checkStatusInMM() err:" + err
            );
        });

   
}
setInterval(function() 
		{checkStatusInMM()
		}, 5 * 1000);