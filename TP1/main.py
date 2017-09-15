from scapy.all import *
from math import log
import sys

broadcastCounter = 0.0
unicastCounter = 0.0
totalCounter = 0.0

broadcastInformation = []
unicastInformation = []
broadcastUnicastArray = []
ipArray = []

ipDictionary = {}

def IpSource(pkt):

	global ipDictionary
	global totalCounter

	if(ipDictionary.has_key(pkt.fields['dst'])):
		ipDictionary[pkt.fields['dst']] += 1.0
	else:
		ipDictionary[pkt.fields['dst']] = 1.0

	enthropy = 0.0
	for k in ipDictionary.keys():
		ipProbability = ipDictionary[k] / totalCounter
		enthropy += ipProbability*log(ipProbability,2)

	ipArray.append(-enthropy)


def broadCastUnicastSource(pkt):

	global broadcastCounter
	global unicastCounter
	global totalCounter

	if pkt.fields['dst'] == 'ff:ff:ff:ff:ff:ff':
		broadcastCounter = broadcastCounter + 1.0
	else:
		unicastCounter = unicastCounter + 1.0

	totalCounter = totalCounter + 1.0

	broadcastProbability = broadcastCounter/totalCounter
	unicastProbability = unicastCounter/totalCounter

	
	if broadcastProbability != 0.0 and unicastProbability != 0.0:
		broadcastInformation.append(-log(broadcastProbability,2))
		unicastInformation.append(-log(unicastProbability, 2))
		enthropy = -(broadcastProbability*log(broadcastProbability,2) + unicastProbability*log(unicastProbability, 2))
		broadcastUnicastArray.append(enthropy)
	else:
		broadcastUnicastArray.append(0.0)
		if broadcastProbability == 0:
			broadcastInformation.append(None)
			unicastInformation.append(0)
		else:
			unicastInformation.append(None)
			broadcastInformation.append(0)
	#print pkt.fields['dst']


def monitor_callback(pkt):
	#print(pkt.fields)
	broadCastUnicastSource(pkt)
	IpSource(pkt)

def printUnicastBroadCastData():
	for x in range(0, len(broadcastUnicastArray)):
		print str(x) + ', ' + str(broadcastUnicastArray[x]) + ', ' + str(broadcastInformation[x]) + ', ' + str(unicastInformation[x])

def main(argc, argv):

	if argc == 2:
		file = sys.argv[1]
		reader = PcapReader(file)
		for p in reader:
			monitor_callback(p)
	else:	
		sniff(prn=monitor_callback, filter="arp", store=0, timeout=600)
	
	printUnicastBroadCastData()

if __name__ == '__main__':
	main(len(sys.argv), sys.argv)
