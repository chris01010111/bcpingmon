#!/usr/bin/env python

"""
    A simple program I wrote for a friend to alert if a remote server stopped responding to pings.
    It accomplishes this by sending a series of pings and logging if the remote host fails to respond to [x] of [n] ICMP Echo requests.
    If SMTP is configured on the local machine, it will send an alert email.
    
    ICMP is handled by the program (raw socket), not via an external call, per IETF RFC 792
    
    Copyright (c) 2015 Chris Whitesell
    May be distributed under the terms of the GNU General Public License version 3; provided with no warranties or assurances of any kind.
"""

import ConfigParser, getopt, os, select, socket, smtplib, struct, sys, time

from datetime import datetime

def main(argv):
    # Process command-line arguments, perform a series of pings, and take appropriate action based on ratio of received:sent
    cfgfile = 'bcpingmon.cfg'
    
    config = ConfigParser.SafeConfigParser({'ServerAddress': '127.0.0.1', 'PingCount': 4, 'AlertThreshold': 2, 'Logfile': 'bcpingmon.log'})
    config.read(cfgfile)
    
    server_addr = config.get('Config', 'ServerAddress')
    ping_count = config.getint('Config', 'PingCount')
    alert_threshold = config.getint('Config', 'AlertThreshold')
    logfile = config.get('Config', 'Logfile')

    # Are we sending alert emails? If yes, get set up for that
    try:
        smtp_server = config.get('Config', 'SMTPServer')
        print "Got SMTP Server: %s" % smtp_server
        send_email = True
    except:
        send_email = False

    if send_email:
        try:
            smtp_from = config.get('Config', 'SMTPFrom')
        except:
            print "FATAL: SMTPServer is set in config file, but SMTPFrom is null or missing!"
            sys.exit(3)
        try:
            smtp_to = config.get('Config', 'SMTPTo')
        except:
            print "FATAL: SMTPServer is set in config file, but SMTPTo is null or missing!"
            sys.exit(3)
        
    # Are there any command line arguments to override our config file?
    try:
        opts, args = getopt.getopt(argv,"hctls",["help","count","threshold","logfile","server"])
    except getopt.GetoptError:
        print_help("Invalid option.")
        sys.exit(2)
    
    for opt, arg in opts:
        print ">> Doing opt loop with opt (%r) and arg (%r)." % (opt, arg)
        if opt in ("-h","--help"):
            print_help()
            sys.exit(0)
        elif opt in ("-c","--count"):
            ping_count = arg
        elif opt in ("-t","--threshold"):
            alert_threshold = arg
        elif opt in ("-l","--logfile"):
            logfile = arg
        elif opt in ("-s","--server"):
            server_addr = arg
    
    # Primary code block. Do the ping loop, log results appropriately
    ping_socket = open_socket()
    ping_replies = 0
    
    for i in xrange(ping_count):
        ping_replies += send_ping(ping_socket, server_addr)
    
    if ping_replies <= (ping_count - alert_threshold):
        write_log(logfile, "FAIL: Host (%s) is DOWN/UNRESPONSIVE (replies below threshold). Responded to %d of %d ICMP Echo (ping) requests." % (server_addr, ping_replies, ping_count))
        if send_email:
            if send_alert(smtp_server, smtp_from, smtp_to, log_entry):
                write_log(logfile, "NOTIFY: Email notification sent. SERVER: %s .. FROM: %s .. TO: %s") % (smtp_server, smtp_from, smtp_to)
            else:
                write_log(logfile, "ALERT: Email notification FAILED. SERVER: %s .. FROM: %s .. TO: %s") % (smtp_server, smtp_from, smtp_to)
        else:
            write_log(logfile, "SKIPPED: Email notification not configured.")
    else:
        log_entry = "SUCCESS: Host (%s) is up. Responded to %d of %d ICMP Echo (ping) requests." % (server_addr, ping_replies, ping_count)
        write_log(logfile, log_entry)
 
    ping_socket.close
    sys.exit(0)

def open_socket():
    icmp = socket.getprotobyname("icmp")

    try:
        main_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error, (errno, errmsg):
        if errno == 1 or errno == 10013:
            errmsg += "\n --> Process must be run as admin/root to send ICMP messages."
            raise socket.error(errmsg)
        raise
    return main_socket

def send_ping(ping_socket, dest_addr):
    packet_ID, ping_packet = construct_packet()
    ping_socket.sendto(ping_packet, (dest_addr, 1))
    return recv_ping(ping_socket, packet_ID)

def construct_packet():
    # Create our packet header
    # Header consists of Type (8b), Code (8b), Checksum (16b), ID (16b), and Sequence (16b)
    # Create a header with an empty checksum, then recreate it with a valid checksum
	ping_ID = os.getpid() & 0xFFFF
	ping_header = struct.pack("bbHHh", 8, 0, 0, ping_ID, 1)
	ping_data = (192 - struct.calcsize("d")) * "P"
	ping_data = struct.pack("d", time.clock()) + ping_data
	ping_checksum = calc_checksum(ping_header + ping_data)
	ping_header = struct.pack("bbHHh", 8, 0, ping_checksum, ping_ID, 1)
	return (ping_ID, (ping_header + ping_data))
	
def calc_checksum(data):
    # Calculate a checksum for the ICMP header
    checksum = 0
    
    for i in range(0, len(data), 2):
        v = ord(data[i]) + (ord(data[i + 1]) << 8)
        checksum = ((checksum + v) & 0xffff) + ((checksum + v) >> 16)
    return ~checksum & 0xffff

def recv_ping(ping_socket, ping_ID):
    # Receive ping reply
    # Used to count number of replies
    recv_timeout = 1
    
    began_listen = time.clock()
    listener = select.select([ping_socket], [], [], recv_timeout)
    wait_duration = (time.clock() - began_listen)
    if listener[0] == []:
        return 0

    recvd_packet, src_addr = ping_socket.recvfrom(1024)
    icmp_header = recvd_packet[20:28]
    icmp_type, icmp_code, icmp_chksum, icmp_ID, icmp_seq = struct.unpack("bbHHh", icmp_header)
    if icmp_ID == ping_ID:
        return 1

    recv_timeout -= wait_duration
    if recv_timeout <= 0:
        return 0
    
def send_alert(smtp_server, smtp_from, smtp_to, msg):
    try:
        smtp_obj = smtplib.SMTP(smtp_server)
        smtp_obj.sendmail(smtp_from, smtp_to, msg)
        return True
    except:
        return False

def write_log(file, msg):
    full_msg = "\n[" + str(datetime.now()) + "] " + msg
    with open(file, 'a') as f:
        f.write(full_msg)
    
def print_help(msg="--> bcpingmon.py help <--"):
   print msg
   print """
   
   bcpingmon.py [-c count] [-t count] [-l path] [-s address]
   
   Typical operation utilizes values from bcpingmon.cfg by default.
   
   Options:
   -h | --help          Present this help
   -c | --count         Number of ICMP Echo requests ("pings") to send
   -t | --threshold     Number of failures at which alert is triggered
   -l | --logfile       Path to log file; defaults to bcpingmon.log
   -s | --server        Address of the host being checked
   """

if __name__ == "__main__":
    main(sys.argv[1:])
