#!/usr/bin/env node
console.log("Welcome to Passive Host Discovey");

var pcap = require('pcap'),
	util = require('util'),
	mysql = require('mysql'),
	program = require('commander');

program
  .version('0.0.1')
  .option('-i, --interface <interface>', 'The network interface to capture from')
  .option('-dbh, --database_host <host>', 'The MySQL database host')
  .option('-dbu, --database_user <username>', 'The MySQL database username')
  .option('-dbp, --database_pass <password>', 'The MySQL database password')
  .option('-dbport, --database_port <port>', 'The MySQL database port')
  .option('-dbd, --database_database <database>', 'The MySQL database to use')
  .option('-dbt, --database_table <table>', 'The MySQL database table')
  .option('-c, --clean', 'Cleans all previous discoveries from the database before start')
  .option('-v, --verbose', 'Will print more information that usual')
  .option('-d, --debug', 'Will print packet data for unparsable packets')
  .option('-a, --all', 'Doesn\'t limit the host discovery to private subnets')
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

capture = pcap.createSession(program.interface, 'ether proto not 0x888e and ether proto not 0x88b7 and ether proto not 0xcccc');

if (program.clean) {
	console.log("- Cleaning...");
	mysqlConnection.query('DELETE FROM ' + mysqlTable);
	console.log("- Cleaning done!");
}

console.log("- Started...");
var startTime = new Date();

capture.on('packet', function (raw_packet) {
	var packet = pcap.decode.packet(raw_packet);
	var sourceMac = "00:00:00:00:00:00";
	var destinationMac = "00:00:00:00:00:00";
	var sourceIp = "0.0.0.0";
	var destinationIp = "0.0.0.0";
	var method = "none";

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
		console.log(util.inspect(packet));
	}

	processInformation(sourceMac, sourceIp, method);
	processInformation(destinationMac, destinationIp, method);
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
			mysqlConnection.query('INSERT INTO ' + mysqlTable + ' VALUES(?, ?) ON DUPLICATE KEY UPDATE ip=?, mac=?',
				[ipAddress ,macAddress, ipAddress, macAddress]);
		}
	}
}

function getTime () {
	return "[" + ((new Date() - startTime)/1000).toFixed(1) + "] ";
}