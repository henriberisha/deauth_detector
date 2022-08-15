import pyshark

# function that prints all the collected APs in the format BSSID : ESSID
# APs are stored in a dictionary with the following layout: access_points = {BSSID as key value : [] list containing ESSID as value for the key}
# chose a list since the testing phase as per possibility of one BSSID containining different EESID
# however, one BSSID can have only one EESID, while one EESID can have multiple BSSID
def print_AP_map(dict_APs):
	for key in dict_APs:
    		print(key, end = " : ")
    		for value in access_points[key]:
        		print(value, end = " ||| ")
        		print()

cap = pyshark.LiveCapture(interface='wlan0')

access_points = {} # will store the collected APs

# dictionary to store deauthentication events with the layout: {"bssid_key" : [essid, counter, [list of client macs being deauthenticated from the bssid_key]]}
# check line 38 to 57 in this code for how the deauths dictionary is populated
deauths = {}

# this is is a continuous live sniff that does an analysis of deauthentication packets every 200 total packets
# inside for loop is responsible for data collection every 200 packets. 200 is chosen arbitrary and can be changed according to the need
# bulk deauth analysis every 200 packets
while True:
	for packet in cap.sniff_continuously(packet_count = 200):
		# any packet with a wlan layer is of interest
		if hasattr(packet, 'wlan'):
			value = packet['wlan'].fc_type_subtype
			value = str(value)
			value_int = int(value, 16) # converting the type to an integer
			
			# reading beacon and probe packets to get the BSSID, and ESSID/ SSID for the networks and building up the APs dictionary
			if value_int == 5 or value_int == 8:
				#print(packet)
				bssid = str(packet['wlan'].bssid) # .bssid is an attribute to get the BSSID from the packet['wlan']
				ssid = str(packet['wlan.mgt'].wlan_ssid) # .wlan_ssid is an attribute to get the name of the network
				if ssid == 'SSID: ': ssid = '<hidden>' # if the result returned is just SSID: that means the name is hidden and that is why the variable ssid is set to <hidden>
			
				if bssid not in access_points: access_points[bssid] = [ssid] # if the bssid is not detected yet, add it as a key in the dictionary
				elif ssid not in access_points[bssid]: access_points[bssid].append(ssid) # if bssid is in the dictionary, add the ssid in the list value for the key
			
			# reading deauthentication packets 
			# otherwise ignore the deauth packets that are going from the client to an AP  as a response
			if value_int == 12:
				bssid = str(packet['wlan'].bssid)
				source_mac = str(packet['wlan'].sa) # reading source mac address
				destination_mac = str(packet['wlan'].da) # reading destination mac address
				
				# to check if the deauth packet is originating from an AP
				if bssid == source_mac:
					
					if bssid in access_points: 
						network_name = access_points[bssid][0] # retreiving the network name from the AP dictionary
					else:
						network_name = "UNKNOWN"
						
					if bssid not in deauths: 
						deauths[bssid] = [network_name, 1, [destination_mac]] # the first deauth packet captured from that bssid, counter value 1 is for the first packet 
					elif destination_mac not in deauths[bssid][2]: # a new client being deauthed from the same AP
						deauths[bssid][1] += 1 # incrementing the counter to show deauth packets originating from the BSSID, and adding the new client MAC
						deauths[bssid][2].append(destination_mac)
					else:
						deauths[bssid][1] += 1 # if the client is already added, just increment the counter for the packets
					# the above code is so that all deauthed clients from the same AP can be picked 
	
	print_AP_map(access_points) #prints the collected APs in the access_points dictionary every 200 packets at the end of the inner for loop
				
	if len(deauths) == 0:
		print("NO DEAUTHENTICATION ACTIVITY HAS BEEN DETECTED YET", end = '\n')
	else:
		print(deauths, end="\n\n")
		for key in deauths:
			if deauths[key][1] > 3: # arbitrary chose that if there are 3 or more deauth packets from the same BSSID, consider it as an attack
				print("SUSPICIOUS DEAUTHENTICATION ACTIVITY DETECTED WITH THE FOLLOWING SPECIFICATIONS:")
				print("From BSSID\t\tWith SSID\t\tTo CLIENT")
				for client in deauths[key][2]:
					print("{}\t\t{}\t\t{}".format(key, deauths[key][0], client))
			else:	# if less than 3 can be considered as a legitimate packet (these values can be changed as I personally chose them, not backed up by any technical detail)
				print("SOME DEAUTHENTICATION ACTIVITY DETECTED WITH THE FOLLOWING SPECIFICATIONS:")
				print("From BSSID\t\tWith SSID\t\tTo CLIENT")
				for client in deauths[key][2]:
					print("{}\t\t{}\t\t{}".format(key, deauths[key][0], client))
		deauths.clear() #clearing all the deaths for that session

	print("\n\n")
        
