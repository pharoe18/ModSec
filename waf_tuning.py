#!/usr/bin/env python
import os
import re
import sys
import csv
import time
from urllib import urlencode
import getopt
''' To DO:
Accept Compressed Files 
Offer whitelisting solution
SSH into device on it's own
 '''

__author__ = "Joshua Roback"

def usage():
	print "****Help****"
	print "Usage: -x or --export to export Tuning Report to CSV"
	print "Usage: -r <ruleID> or --rule <ruleID> to output only a single rule ID"
	print "Usage: -c <n> or --count <n> to output alert count <n>"
	print "Usage: -a to print raw Attack Matrix to terminal"
	print "Usage: -s or --summery to display the attack summery"
	print "Usage: -h or --help to display this help message"
	return

def openFile():
	path = raw_input("What is the location of your audit log file? ")
	#path = 'modsec_audit.log' #DEBUG for quick testing
	while (os.path.isfile(path) == False):
		path = raw_input("No audit file seems to exist in that location.  Try again! ")
	try:
		auditFile = open(path, 'r')
	except IOError:
		print "Count not open file."
	return auditFile

def findDelims(auditFile):
	delimList = []
	delimRegex = re.compile(r'--([a-z0-9]{8})-([A])--')
	for current_line in auditFile:
		delim = delimRegex.search(current_line)
		if delim:
			delimList.append(delim.group(1))
	return delimList

def findAlert(auditFile, delimList, c):
	auditFile.seek(0)
	for i in range(len(delimList)):
		current_alert = ""
		for current_line in auditFile:
			startline = "--%s-A--" % (delimList[i])
			endline = "--%s-Z--" % (delimList[i])
			ruleline = "--%s-H--" % (delimList[i])
			current_alert += current_line
			if (current_line.rstrip('\n') == endline):
				#print current_line # DEBUG - Good for grabbing last alert that failed
				parseAlert(current_alert, delimList[i])
				break
		if c != False:
			c = c - 1
			if c == 0:
				break
	return

def parseAlert(current_alert, delim):
	count = 1
	allAlerts = re.findall('Message: Warning.*id \"\d+\".*msg \"[^\"]+', current_alert)
	for j in allAlerts:
		message = "*"*100+"\n"
		list_alert = re.split(delim,current_alert)
		sipRegex = re.search(r'(\d+\.\d+\.\d+\.\d+)',list_alert[1])
		sip = sipRegex.group()
		methodUriRegex = re.search(r'([A-Z]+) (.+?(?=\sHTTP)) HTTP',list_alert[2])
		method = methodUriRegex.group(1)
		uri = methodUriRegex.group(2)
		hostRegex = re.search(r'Host: ([^\s]+)', list_alert[2])
		if hostRegex:
			host = hostRegex.group(1)
		else:
			host = "none"
		rule_type = re.search('Message: Warning\. ([^"]\w+ \w+)', j)
		rule_parse = re.search('Message: Warning.*id \"(\d+)\".*msg \"([^\"]+)', j)
		if rule_parse:
			ruleID = rule_parse.group(1)
			ruleMSG = rule_parse.group(2)
		if rule_type:
			if rule_type.group(1) == "Matched phrase":
				check_phrase = re.search('Matched phrase "(.*)" at (.+?(?=\.\s))', j)
				pattern = check_phrase.group(1)
				location = check_phrase.group(2)
				rule_type = "Matched phrase"
				location_parts = re.split(r':',location)
				attack_part = location_parts[0]
				attack_location = location_parts[1]
			elif rule_type.group(1) == "Pattern match":
				check_phrase = re.search('Pattern match "(.*)" at (.+?(?=\.\s))', j)
				pattern = check_phrase.group(1)
				location = check_phrase.group(2)
				rule_type = "Pattern match"
				location_parts = re.split(r':',location)
				attack_part = location_parts[0]
				if attack_part == "REQUEST_FILENAME":
					attack_location = uri
				elif attack_part == "ARGS":
					attack_location = location_parts[1]+"="
				elif attack_part == "RESPONSE_BODY":
					attack_location = "It's in the RESPONSE BODY.  Look there!"
				else:
					attack_location = location_parts[1]
			elif rule_type.group(1) == "Match of":
				check_phrase = re.search('Match of "(.*)" against (.+?(?=\.\s))', j)
				pattern = check_phrase.group(1)
				location = check_phrase.group(2)
				rule_type = "Match of"
				attack_part = ""
				attack_location = ""
				raw_attack = ""
		else:
			if s == True and r == "all":
				print "Could not parse :("
				rule_type = re.search('Message: ([^\n])+', j)
	 			print rule_type.group()
			return
	#		user_debug = raw_input("COULD NOT PARSE!!!! type \"quit\" to exit")
	#		if user_debug == "quit":
	#			sys.exit(2)
		compositeKey = ruleID+ruleMSG+attack_part
		if r != 'all':
			if r == ruleID:
				message += "Source IP: %s\n" % (sip)
				message += "Host: %s\n" %(host)
				message += method+" "+uri+"\n"
				message += "Rule: %s %s\n" % (ruleID, ruleMSG)
				message += "The pattern \"%s\" is located at %s\n" % (pattern, location)
				#print message #DEBUG
				if rule_type == "Pattern match" or rule_type == "Matched phrase":
					attack_string = re.search(re.escape(attack_location)+"[^&\n]*", current_alert)
					if attack_string:
						raw_attack = attack_string.group()
						message += raw_attack+"\n"
					else:
						raw_attack = ""
						message += raw_attack+"\n"
				message += "*"*100+"\n"
				attackDetails = {'sip' : sip, 'host' : host, 'method' : method, 'uri' : uri, 
				'ruleID' : ruleID, 'ruleMSG' : ruleMSG, 'attack_part' : attack_part, 
				'attack_location' : attack_location, 'raw_attack' : raw_attack
				}
				attackMatrix[delim+"!"*count] = attackDetails
				if s == True:
					print message
			count +=1
		else:
			message += "Source IP: %s\n" % (sip)
			message += "Host: %s\n" %(host)
			message += method+" "+uri+"\n"
			message += "Rule: %s %s\n" % (ruleID, ruleMSG)
			message += "The pattern \"%s\" is located at %s\n" % (pattern, location)
			if rule_type == "Pattern match" or rule_type == "Matched phrase":
				attack_string = re.search(re.escape(attack_location)+"[^&\n]*", current_alert)
				if attack_string:
					raw_attack = attack_string.group()
					message += raw_attack+"\n"
				else:
					raw_attack = ""
					message += raw_attack+"\n"
			message += "*"*100+"\n"
			attackDetails = {
			'sip' : sip, 'host' : host, 'method' : method, 'uri' : uri, 
			'ruleID' : ruleID, 'ruleMSG' : ruleMSG, 'attack_part' : attack_part, 
			'attack_location' : attack_location, 'raw_attack' : raw_attack
			}
			attackMatrix[delim+"!"*count] = attackDetails
			if s == True:
				print message
			count += 1
	return 

def writeCSV(attackMatrix):
	outFile = open("Tuning_Report"+time.strftime("%Y-%M-%d_%H-%M-%S")+".csv", "w")
	writer = csv.writer(outFile, quoting=csv.QUOTE_ALL)
	writer.writerow(['delimiter', 'sip', 'host', 'method', 'uri', 'ruleID', 'ruleMSG', 'attack_part', 'attack_location', 'raw_attack'])
	for key in attackMatrix:
		if r != 'all':
			if attackMatrix[key]['ruleID'] == r:
				writer.writerow([key, attackMatrix[key]['sip'], attackMatrix[key]['host'], attackMatrix[key]['method'], attackMatrix[key]['uri'], attackMatrix[key]['ruleID'], attackMatrix[key]['ruleMSG'], attackMatrix[key]['attack_part'], attackMatrix[key]['attack_location'], attackMatrix[key]['raw_attack']])
			else:
				next
		else:
			writer.writerow([key, attackMatrix[key]['sip'], attackMatrix[key]['host'], attackMatrix[key]['method'], attackMatrix[key]['uri'], attackMatrix[key]['ruleID'], attackMatrix[key]['ruleMSG'], attackMatrix[key]['attack_part'], attackMatrix[key]['attack_location'], attackMatrix[key]['raw_attack']])
	outFile.close()
	print "Exported Attack Matrix as Tuning_Report-%s.csv" % (time.strftime("%Y-%m-%d_%H-%M-%S"))

def printMatrix(attackMatrix):
	for key in attackMatrix:
		for value in attackMatrix[key]:
			if r != 'all':
				if attackMatrix[key][value] == r:
					print key+":"+value+":"+attackMatrix[key][value]
				else:
					next
			else:
				print key+":"+value+":"+attackMatrix[key][value]




r = 'all'
x = False
a = False
s = False
c = False
attackMatrix = {}
attackDetails = {}
message = ""

try:
	opts, args = getopt.getopt(sys.argv[1:],'xc:r:ahs',["export","count=","rule=","help", "summery"])
except getopt.GetoptError:
	usage()
	sys.exit(2)
for opt, arg in opts:
	if opt in ('-h','--help'):
		usage()
		sys.exit(2)
	if opt in ('-x',"--export"):
		x = True
	if opt in ("-c","--count"):
		c = int(arg)
	if opt in ("-r","--rule"):
		r = arg
	if opt == "-a":
		a = True
	if opt in ("-s","--summery"):
		s = True

auditFile = openFile()
delimList = findDelims(auditFile)
findAlert(auditFile, delimList, c)
auditFile.close()
if a == True:
	printMatrix(attackMatrix)
if x == True:
	writeCSV(attackMatrix)

	
