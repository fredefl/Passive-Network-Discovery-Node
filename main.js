#!/usr/bin/env node
console.log("Welcome to Passive Network Discovey");

var pcap = require('pcap'),
	util = require('util'),
	mysql = require('mysql'),
	program = require('commander');

program
  .version('0.0.1')
  .option('-i, --interface <interface>', 'network interface to capture from')
  .option('-dbh, --database_host <host>', 'MySQL database host')
  .option('-dbu, --database_user <username>', 'MySQL database username')
  .option('-dbp, --database_pass <password>', 'MySQL database password')
  .option('-dbport, --database_port <port>', 'MySQL database port')
  .option('-dbd, --database_database <database>', 'MySQL database/schema')
  .option('-dbt, --database_table <table>', 'MySQL database table')
  .option('-c, --clean', 'clean start, clears the database')
  .option('-v, --verbose', 'print more information than usual')
  .option('-d, --debug', 'print packet data for unparsable packets')
  .option('-a, --all', 'don\'t limit the host discovery to private subnets')
  .parse(process.argv);

if (!program.interface) {
	console.log("  No interface specified!");
	program.help();
}

var mysqlTable = (program.database_table ? program.database_table : 'hosts');
var mysqlConnection = mysql.createConnection({
  host		: (program.database_host ? program.database_host : 'localhost'),
  user		: (program.database_user ? program.database_user : 'root'),
  password	: (program.database_pass ? program.database_pass : ''),
  port		: (program.database_port ? program.database_port : 3306),
  database	: (program.database_database ? program.database_database : 'passive_network_discovery')
});

console.log("- Connecting to MySQL database...");
mysqlConnection.connect();
console.log("- Connected to MySQL database!");

//capture = pcap.createSession(program.interface, 'ether proto not 0x888e and ether proto not 0x88b7 and ether proto not 0xcccc');
capture = pcap.createSession(program.interface, 'port 137');

if (program.clean) {
	console.log("- Cleaning...");
	mysqlConnection.query('DELETE FROM ' + mysqlTable);
	console.log("- Cleaning done!");
}

console.log("- Started...");
var startTime = new Date();

capture.on('packet', function (raw_packet) {
	var packet;
	try {
		packet = pcap.decode.packet(raw_packet);
	} catch (ex) {
		console.log(ex);
	}
	var sourceMac = "00:00:00:00:00:00";
	var destinationMac = "00:00:00:00:00:00";
	var sourceIp = "0.0.0.0";
	var destinationIp = "0.0.0.0";
	var method = "none";
	var netbiosName = null;
	try {
		if (typeof packet.link.arp != 'undefined') {
			sourceMac = packet.link.arp.sender_ha;
			sourceIp = packet.link.arp.sender_pa;

			destinationMac = packet.link.arp.target_ha;
			destinationIp = packet.link.arp.target_pa;

			method = "arp";
		} else {
			sourceMac = packet.link.shost;
			destinationMac = packet.link.dhost;
			if (typeof packet.link.ip != 'undefined') {
				sourceIp = packet.link.ip.saddr;
				destinationIp = packet.link.ip.daddr;

				method = "ipv4";
			} else if (typeof packet.link.ipv6 != 'undefined') {
				sourceIp = packet.link.ipv6.saddr;
				destinationIp = packet.link.ipv6.daddr;

				method = "ipv6";
			} else {
				if (program.debug)
					console.log(util.inspect(packet));
			}
		}
	} catch (error) {
		console.log(error);
		console.log(util.inspect(packet));
	}

	try {
		if (typeof packet.link.ip.udp != 'undefined' && packet.link.ip.udp.dport == 137 && packet.link.ip.udp.length == 76) {
			// From [13] to [12+32]
			var netbiosName = "";
			for (var i = 13; i <= 13 + 31; i += 2) {
				var character = "";
				var characterHex = packet.link.ip.udp.data[i].toString(16) + packet.link.ip.udp.data[i+1].toString(16);
				if (characterHex in characterArray)
					character = characterArray[characterHex];
				netbiosName += character;
			}
			netbiosName = netbiosName.replace(/^(\s*)((\S+\s*?)*)(\s*)$/,"$2");
		}
	} catch (ex) {
		console.log("Error in Netbios parsing", ex);
	}

	processInformation(sourceMac, sourceIp, method);
	processInformation(destinationMac, destinationIp, method);
	if (netbiosName !== null) 
		processNetbiosName((sourceMac, sourceIp, method, netbiosName);
});

function processInformation (macAddress, ipAddress, method) {
	if (macAddress !== 'ff:ff:ff:ff:ff:ff' && macAddress !== '00:00:00:00:00:00') {
		if (program.all || ipAddress.match("(^10\.[0-9])|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^fe80)")) {
			if (program.verbose || program.debug)
				console.log(getTime() + "Host discovered (debug): " + method + "\t" + macAddress + "\t" + ipAddress);
			mysqlConnection.query('SELECT count(*) FROM ' + mysqlTable + ' WHERE ip=? OR mac=?', [ipAddress, macAddress],
				function(err, rows, results) {
				var rowCount = rows[0]['count(*)'];

				if (rowCount === 0) {
					// It's a new host!
					console.log(getTime() + "New host discovered: " + method + "\t" + macAddress + "\t" + ipAddress);
				}
			});
			mysqlConnection.query('INSERT INTO ' + mysqlTable + ' (ip, mac, method) VALUES(?, ?, ?) ON DUPLICATE KEY UPDATE ip=?, mac=?, method=?',
				[ipAddress, macAddress, method, ipAddress, macAddress, method]);
		}
	}
}

function getTime () {
	return "[" + ((new Date() - startTime)/1000).toFixed(1) + "] ";
}

var characterArray = {"4542":"A","4543":"B","4544":"C","4545":"D","4546":"E","4547":"F","4548":"G","4549":"H","454a":"I","454b":"J","454c":"K","454d":"L","454e":"M","454f":"N","4550":"O","4641":"P","4642":"Q","4643":"R","4644":"S","4645":"T","4646":"U","4647":"V","4648":"W","4649":"X","464a":"Y","464b":"Z","4441":"0","4442":"1","4443":"2","4444":"3","4445":"4","4446":"5","4447":"6","4448":"7","4449":"8","444a":"9","4341":" ","4342":"!","4343":"\"","4344":"#","4345":"$","4346":"%","4347":"&","4348":"'","4349":"(","434a":")","434b":"*","434c":"+","434d":",","434e":"-","434f":".","444e":"=","444b":":","444c":";","4541":"@","464f":"^","4650":"_","484c":"{","484e":"}","484f":"~"};