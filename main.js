#!/usr/bin/env node

var pcap = require('pcap'),
	util = require('util'),
	mysql = require('mysql'),
	program = require('commander');

program
  .version('0.0.1')
  .option('-i, --interface <interface>', 'The network interface to capture from')
  .parse(process.argv);

if (!program.interface) {
	program.help();
}

var mysqlTable = 'hosts';
var mysqlConnection = mysql.createConnection({
  host		: 'localhost',
  user		: 'root',
  password	: '',
  port		: 3306,
  database	: 'passive_network_discovery'
});

mysqlConnection.connect();

capture = pcap.createSession(program.interface, 'ether proto not 0x888e and ether proto not 0x88b7 and ether proto not 0xcccc');

console.log("Started...");

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
				//console.log(util.inspect(packet));
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
		if (ipAddress.match("(^10.)|(^172.1[6-9].)|(^172.2[0-9].)|(^172.3[0-1].)|(^192.168.)|(^fe80)")) {
		
			mysqlConnection.query('SELECT count(*) FROM ' + mysqlTable + ' WHERE ip=? OR mac=?', [ipAddress, macAddress], function(err, rows, results) {
				var rowCount = rows[0]['count(*)'];

				if (rowCount == 0) {
					// It's a new host!
					console.log("New host discovered: " + method + "\t" + macAddress + "\t" + ipAddress);
				}
			});

			mysqlConnection.query('INSERT INTO ' + mysqlTable + ' VALUES(?, ?) ON DUPLICATE KEY UPDATE ip=?, mac=?', [ipAddress ,macAddress, ipAddress, macAddress], function(err, rows, results) {

			});
		}
	}
}