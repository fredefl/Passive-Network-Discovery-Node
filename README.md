Passive Network Discovery - Node
==============================

Usage
--------------------------------------

To capture packets from `eth0` with default MySQL settings:

    sudo ./main.js -i eth0
    
or
    
    sudo node main.js -i eth0

If you want to change the connection parameters of the MySQL database or want to get more fancy, take a look at the command line options below.

Heads up!
--------------------------------------
**In most cases packet capture in *nix requires root privileges, so make sure to run the tool with `sudo` or as root!**

Command line options
--------------------------------------
    -h, --help                            output usage information
    -V, --version                         output the version number
    -i, --interface <interface>           network interface to capture from
    -dbh, --database_host <host>          MySQL database host
    -dbu, --database_user <username>      MySQL database username
    -dbp, --database_pass <password>      MySQL database password
    -dbport, --database_port <port>       MySQL database port
    -dbd, --database_database <database>  MySQL database/schema
    -dbt, --database_table <table>        MySQL database table
    -c, --clean                           clean start, clears the database
    -v, --verbose                         print more information than usual
    -d, --debug                           print packet data for unparsable packets
    -a, --all                             don't limit the host discovery to private subnets

Database
--------------
To create the MySQL database, use:

    delimiter $$

    CREATE TABLE `hosts` (
      `ip` varchar(45) NOT NULL DEFAULT '',
      `mac` varchar(17) NOT NULL DEFAULT '',
      `method` varchar(10) DEFAULT NULL,
      `netbiosName` varchar(16) DEFAULT NULL,
       PRIMARY KEY (`mac`,`ip`),
       UNIQUE KEY `ip_UNIQUE` (`ip`)
    ) ENGINE=InnoDB DEFAULT CHARSET=latin1$$

Dependencies
--------------------------------------

 - **nodejs** No shit sherlock
 - **node_pcap** Used to capture the all important packets with node
 - **node_util** Used to inspect packets (debug)
 - **node_mysql** Used to store discovered hosts
 - **node_commander** Used to create the nice command line option interface
 - **libpcap** Used to capture packets
 
You will need to have a MySQL server running in order for it to work.
You will also in most cases need root access.

License
-------------------------------------
Copyright (C) 2013 Frederik Fredslund Lassen <frederiklassen@gmail.com>
https://illution.dk

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

