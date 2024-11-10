#!/usr/bin/env python3
#Parses an .out file and caculates stats
#syntax: python3 parsedump.py [file] [srcIP] [dstIP] [bytes per swID=2] [method(dlint/plint)+values(1-5)] [pu timestamp]
#example: python3 parsedump.py s12-eth2 10.0.1.1 10.0.1.12 2 dlint1 0

import re, sys, os, time, math
from datetime import datetime, timedelta
                 
if len(sys.argv)<4: #Wrong parameters
	exit()

filename = sys.argv[1]
srcIP = sys.argv[2]+'.'
dstIP = sys.argv[3]+'.'
if len(sys.argv[4])>0:
	bytesLabel = int(sys.argv[4])
if len(sys.argv)>5:
	values = int(sys.argv[5][-1])
	intType = True if (sys.argv[5][:-1]=='dlint') else False
else:
	values = 1
if len(sys.argv)>6:
	PUtime=sys.argv[6]

timeFormat='%H:%M:%S.%f'


#Decode pcap dump
os.system('tcpdump \'ip proto \\tcp\' -nnvvXSs 80 -r ./pcaps/'+filename+'_in.pcap >temp_in.out')
os.system('tcpdump \'ip proto \\tcp\' -nnvvXSs 80 -r ./pcaps/'+filename+'_out.pcap >temp_out.out')	
fileIN = open('temp_in.out', "r") 
fileOUT = open('temp_out.out', "r")


paths = {} #Dictionary with pair of IPs as key and the string of INT swIDs
pathshop = {} #Dictionary with pair of IPs as key and the string of hop counts (for plint implementation)
timestamps = {} #Dictionary with pair of IPs as key and the string of timestamps
altSignature=""


#Function to reverse IP and port
def revKey(k):
  return k[k.find('>')+2:]+' > '+k[:k.find('>')-1]

#Function to calculate the timestamp of the first occurance of path update
#Find timestamps of all swIDs in AltSignature. The minimum one is when the path Update tool place
def calcMinPUtimestamp():	
	minim='a'		
	for key, value in paths.items():		
		if key.startswith(srcIP):
			value=value.replace(' ','')
			value=value.replace('*','')
			value=value.replace('f'*bytesLabel,'')
			value=value.replace('e'*bytesLabel,'')
			for i in range(0,len(altSignature),bytesLabel):
				s=altSignature[i:i+bytesLabel]
				#print(value.find(s))
				if value.find(s)>-1:
					ts=timestamps[key][value.find(s)//bytesLabel]
					if ts<minim: minim=ts
	if minim=='a':
		minim='0:0:0.0'
	return minim

	#Function to calc interval between two timestamps w2-w1
def interval(w1,w2):
	w1l=datetime.strptime(w1,timeFormat).time()
	w2l=datetime.strptime(w2,timeFormat).time()
	w1t = timedelta(hours=w1l.hour, minutes=w1l.minute, seconds=w1l.second, microseconds=w1l.microsecond)
	w2t = timedelta(hours=w2l.hour, minutes=w2l.minute, seconds=w2l.second, microseconds=w2l.microsecond)
	if w2l.hour==00 and w1l.hour==23:
		w2t=w2t+timedelta(days=1)

	df=w2t-w1t
	totalMSec=int(df/timedelta(microseconds=1))

	return totalMSec


#Function to calc Hop number for rightDst path
def calcRightHop(rightPth):
	rPth=''
	for i in range(0,len(rightPth),bytesLabel):
		rPth+=str(hex(i//bytesLabel))[2:].zfill(2)

	return rPth

srcString=''
dstString=''
numOfPackets=0
numOfINT=0
extraINT=0
totDuplicates=0



#The correct path for each IP pair is:
if bytesLabel==2:	
	if srcIP=='10.0.1.1.' and dstIP=='10.0.1.12.':
		rightDst="000102030405060708090a0b"
		altDst=  "0001020304050607080e090a0b"
		altSignature="0e"
	if srcIP=='10.0.1.21.' and dstIP=='10.0.1.3.':
		rightDst="001516171b1a11100e0504"
		altDst=  "001516171b1a1918130d04"
		altSignature="1918130d"
	if srcIP=='10.0.1.8.' and dstIP=='10.0.1.17.':
		rightDst="00080e0f13141516171b1a"
		altDst=  "00080e0f1318171b1a"
		altSignature="18"
	if srcIP=='10.0.1.18.' and dstIP=='10.0.1.9.':
		rightDst="00121318171b19100c0b0a"
		altDst=  "00121316171b19100c0b0a"
		altSignature="16"

rightDstHop=calcRightHop(rightDst)
altDstHop=calcRightHop(altDst)

#print(rightDst, rightDstHop)
#print(altDst, altDstHop)

#print(interval('23:59:59.820719','00:00:00.820719'))

#**************** Parse INT headers from Packets, store in "paths" list ******************
lineIN = fileIN.readline()
lineOUT = fileOUT.readline()
while lineIN or lineOUT:
	#Find first appropriate IP line in both files
	while lineIN and (lineIN.find(srcIP)<0 or lineIN.find(dstIP)<0 or lineIN.find('.9000')>-1) : #While dst or src IPs are not found (keep reding until you find one)		
		prevLineIN=lineIN
		lineIN = fileIN.readline()
	timestIN=prevLineIN[:prevLineIN.find(' IP (tos')]

	while lineOUT and (lineOUT.find(srcIP)<0 or lineOUT.find(dstIP)<0 or lineOUT.find('.9000')>-1) : #While dst or src IPs are not found (keep reding until you find one)		
		prevLineOUT=lineOUT
		lineOUT = fileOUT.readline()	
	timestOUT=prevLineOUT[:prevLineOUT.find(' IP (tos')]

	#print(timestIN,timestOUT,interval(timestIN,timestOUT))
	#if not lineOUT or not lineIN: 
	#	print('lineIn:'+lineIN)
	#	print('lineOut:'+lineOUT)
	if (not lineOUT) or (lineIN and interval(timestIN,timestOUT)>0):		
		file=fileIN
		line=lineIN
		timest=timestIN
	else:
		#print('out')
		file=fileOUT
		line=lineOUT
		timest=timestOUT
	
	ipline=line    #Line with IPs
	#print(ipline+' | ',end="")
	#Scroll to find intline
	while line and line.find('0x0020:')<0: #Line where INT packets reside
		line = file.readline()	
	intline = line  #Line with INT packet

	if len(intline)>11:
		#print(ipline,intline)
		key=ipline[4:ipline.find(':')]
		reverseKey=revKey(key)    #Reverse IPs
		if key not in paths:
			paths[key]=""					#String with switch IDs
			paths[reverseKey]=""	#String with switch IDs of reversed path
			pathshop[key]=""			#String with hop counting (for plint case)
			pathshop[reverseKey]=""	#Hop counting for reversed path
			timestamps[key]=[]			#Timestamps tuple (one for each hop)
			timestamps[reverseKey]=[]
			#print(key,reverseKey)
			#raw_input("Press Enter to continue...")

		if key.startswith(srcIP):
			numOfPackets+=1
		if len(intline)<31: print("IntLine:"+intline)
		if intline[11]=='8':     #Contains INT value
			if key.startswith(srcIP):
				numOfINT+=1			
			if intType: 			#DLINT case				
				try:
					paths[key]+=intline[32-bytesLabel:32]
					if values>1: paths[key]+=intline[34-bytesLabel:34] 
					if values>2: paths[key]+=intline[37-bytesLabel:37] 
					if values>3: paths[key]+=intline[39-bytesLabel:39] 
					if values>4: paths[key]+=intline[42-bytesLabel:42]			
				except IndexError as err:
					print(err)
					print("IntLine:"+intline)
				paths[reverseKey]+=' '*values*bytesLabel
			else:				#PLINT case
				paths[key]+=intline[34-bytesLabel:34]
				pathshop[key]+=intline[37-bytesLabel:37]
				if values>1:
					paths[key]+=intline[39-bytesLabel:39]
					pathshop[key]+=intline[42-bytesLabel:42]
				if values>2:
					paths[key]+=intline[44-bytesLabel:44]
					pathshop[key]+=intline[47-bytesLabel:47]
				if values>3:
					paths[key]+=intline[49-bytesLabel:49]
					nextline=file.readline()
					pathshop[key]+=nextline[12-bytesLabel:12]
				if values>4:
					paths[key]+=nextline[14-bytesLabel:14]
					pathshop[key]+=nextline[17-bytesLabel:17]
				paths[reverseKey]+=' '*values*bytesLabel
				#Calculate Duplicate values
				if key.startswith(srcIP):
					allkeysString=paths[key][-values*bytesLabel:]
					allkeys=[allkeysString[i:i+bytesLabel] for i in range(0,values*bytesLabel,bytesLabel)]
					totDuplicates+=values-len(list(set(allkeys)))
					#print(allkeysString, allkeys, totDuplicates)
			#Append timestamps excluding ffs and ees
			timstNum=values-paths[key][-values*bytesLabel:].count('f'*bytesLabel)-paths[key][-values*bytesLabel:].count('e'*bytesLabel)
			for x in range(timstNum):
				timestamps[key].append(timest)			
		else:							#non-INT value
			#Find last node of the previous packet
			if intType and key.startswith(srcIP):
				i=len(paths[key])-bytesLabel
				while i>=0 and paths[key][i:i+bytesLabel]==' '*bytesLabel:
					i=i-bytesLabel
				lastnode=paths[key][i:i+bytesLabel]				
				if lastnode==rightDst[-bytesLabel:]: extraINT+=1 		#if previous packet ended with last switchID of the path
			paths[key]+='*'*bytesLabel + ' '*(values-1)*bytesLabel				#Non-INT packet
			paths[reverseKey]+=' '*values*bytesLabel											#Leave space to align with reverse
			pathshop[key]+='*'*bytesLabel + ' '*(values-1)*bytesLabel				#Non-INT packet
			pathshop[reverseKey]+=' '*values*bytesLabel										#Leave space to align with reverse		
	if file==fileIN:
		lineIN = fileIN.readline() 
	else:	
		lineOUT = fileOUT.readline()
	
fileIN.close()
fileOUT.close()

#-----Check weather timestamps are out of sync and calculate INT packets
valuableINT=0 	#pure swIDs without reset,init or balnks
for key, value in paths.items():
	if key.startswith(srcIP):
		v=value
		v=v.replace(' ','')
		v=v.replace('*','')
		v=v.replace('f'*bytesLabel,'')
		v=v.replace('e'*bytesLabel,'')
		#print(len(v),len(timestamps[key]))
		if len(v)//bytesLabel!=len(timestamps[key]): 
			print('TimeStamps out of sync! ! ! ! ! ! ! !')
			exit()
		
		#Remove INIT signals
		init=v.find('0'*bytesLabel)
		while init>-1:
			if init % bytesLabel==0:
				v=v[:init]+v[init+bytesLabel:]   #Remove Init signal
			init=v.find('0'*bytesLabel,init+1)
		valuableINT+=len(v)//bytesLabel

#print(paths)
#exit()

#Set the time stamp of the PU
if len(sys.argv)>6:
	minPUtimestamp=PUtime
else:
	minPUtimestamp=calcMinPUtimestamp()
print(minPUtimestamp)

#*********************Analyze paths list**********************
totAccurate=0
totInaccurate=0
totFoundLabels=0
totLostLabels=0
totLostReset=0
altPath=0
altPathUn=0
sumTimeLapse=0
sumTimeLapseUn=0
totRemaining=0
timeLapses=[]
if intType :  #********** DLINT implementation **********
	for key, value in paths.items():
		if key.startswith(srcIP):

			#To Print all telemetry values uncomment the following 6 commented lines
			#print(key, value, len(value.replace(' ',''))//bytesLabel)			
			#print(len(timestamps[key]))
			#if not intType: print(key, pathshop[key]) 
			rkey=revKey(key)
			#print(rkey, paths[rkey], len(value.replace(' ',''))//bytesLabel)
			#if not intType: print(rkey, pathshop[rkey]) 
			#print('')
			
			dstPath=paths[key]											#dstPath = string of swIDs

			dstPath=dstPath.replace(' ','')					#Remove blanks
			if dstPath.find('*'*(len(rightDst)*2)*bytesLabel)>-1:		#If too many non-INT, possible SimpleSwitch overwhelm (reduce packet rate)
				print("***TOO MANY NON-INT PACKETS***")
				#print(key, value, len(value.replace(' ','')))
				#print(rkey, paths[rkey], len(value.replace(' ','')))
				#print('')		
			inaccurateDst=dstPath.count('*'*len(rightDst)*bytesLabel)	#Continuous path-length * are inaccurate paths
			if inaccurateDst>2:
				print("---Lost reset----")
				totLostReset+=1
				print(key, value, len(value.replace(' ','')))
				print(rkey, paths[rkey], len(value.replace(' ','')))
			#print('*',inaccurateDst)
			
			#-----Path Update Analysis-----
			dstPath=dstPath.replace('*','')					#Remove non-INTs
			dstPath=dstPath.replace('f'*bytesLabel,'')					#Remove Resets
			dstPath=dstPath.replace('e'*bytesLabel,'')					#Remove Unused
			
			#-----Path Update Analysis based on ordered switch IDs						
			if (dstPath.find(rightDst[bytesLabel:])>-1 and dstPath.find(altDst[bytesLabel:])>-1 and key.find('.9000')==-1):		#If path update took place in this flow (and the flow is not the monitoring flow)
				currentTS=timestamps[key][((dstPath.find(altDst[bytesLabel:])+len(altDst)-bytesLabel)//bytesLabel)-1]		#Timestamp of the last node of the path

				timeLapse=interval(minPUtimestamp,currentTS)
				sumTimeLapse+=timeLapse
				timeLapses.append(timeLapse)
				print('TimeLapse= '+str(timeLapse)) #, timeLapsePrev)
				if timeLapse>999999: 
					print('Too long time', key, dstPath)
					duration=interval(timestamps[key][0],timestamps[key][-1])
					print(duration)
				altPath+=1					

			
			#-----------------------Path Accuracy Analysis--------------------
			#print(minPUtimestamp)
			if minPUtimestamp=='0:0:0.0':				#No Alt path found
				accurateDst=dstPath.count(rightDst)				#accurateDst = Count right paths
				#print(dstPath)
				foundLabels=accurateDst*len(rightDst)//bytesLabel			#Foundlabels = swIds that form paths even if they are unordered
				dstPath=dstPath.replace(rightDst,'')			#...and remove them	
				dstPath=dstPath.replace('0'*bytesLabel,'')						# Remove zero left-overs
				inaccurateDst+=len(dstPath)//len(rightDst[bytesLabel:])		#Left-overs are inacurate paths
				
				accurateDst+=dstPath.count(rightDst[bytesLabel:])		#Count paths without inits
				if (len(dstPath)//len(rightDst[bytesLabel:])>0):
					print(key, value, len(value.replace(' ','')))
					print(rkey, paths[rkey], len(value.replace(' ','')))
					print('Innac = '+str(len(dstPath)//len(rightDst[1:])))
					print('Remaining: '+dstPath+' '+str(len(dstPath))+' Innacc:'+str(inaccurateDst)) 
					print('')		
				foundLabels+=dstPath.count(rightDst[bytesLabel:])*len(rightDst[bytesLabel:])
				dstPath=dstPath.replace(rightDst[bytesLabel:],'')		#...and remove them

				#----------------------Remaining Calculation----------------------
				#List of all swIds of rightDst and altDst 
				pathids = [rightDst[i:i+bytesLabel] for i in range(0,len(rightDst),bytesLabel)]
				
				remainingDstPath = '' #dstPath
				rightPathPresent=False
				pathUpdate=False

				for i in range(0,len(dstPath),bytesLabel):
					swid=dstPath[i:i+bytesLabel]
					if swid in pathids:	
						pathids.remove(swid)
					else:
						remainingDstPath+=swid					
					if not pathids:
						countRightPaths+=1
						pathids = [rightDst[i:i+bytesLabel] for i in range(0,len(rightDst),bytesLabel)] #Initialize pathids
						rightPathPresent=True
				
				if (len(remainingDstPath)//bytesLabel>len(rightDst[bytesLabel:])):		#If remaining is more than a path's length
					totRemaining+=len(remainingDstPath)//bytesLabel
				#-----------------------------------------------------------------
			
				#Calculate lost Labels (ie swIDs)	
				occurrancies = [dstPath.count(rightDst[x:x+bytesLabel]) for x in range(bytesLabel,len(rightDst),bytesLabel)]         #List with number of occurancies for every path swID
				minimum = min(occurrancies)
				foundLabels+=minimum*len(rightDst[bytesLabel:])//bytesLabel				#Labels that form paths but unordered
				occurrancies = [x-minimum for x in occurrancies]		#Orphan swIds
				shouldBe=sum(occurrancies)//(len(rightDst)//bytesLabel-1)	#Num of paths if they were accurate
				lostLabels=0																				#lostLabes = swIds that do not form paths
				for item in occurrancies:
					if item<shouldBe:
						lostLabels+=shouldBe-item
						foundLabels+=item
					else:
						foundLabels+=shouldBe

				if lostLabels<len(rightDst)//bytesLabel-1:	lostLabels=0

				totFoundLabels+=foundLabels
				totLostLabels+=lostLabels
				#print('foundLabels= '+str(foundLabels)+" lostLabels="+str(lostLabels))

				totAccurate+=accurateDst
				totInaccurate+=inaccurateDst
				
			
else:		#***********PLINT Implementation**************
	rightDst = rightDst[bytesLabel:]          #.replace('0'*bytesLabel,'')
	altDst = altDst[bytesLabel:] 							#.replace('0'*bytesLabel,'')
	rightDstHop = rightDstHop[bytesLabel:]          #.replace('0'*bytesLabel,'')
	altDstHop = altDstHop[bytesLabel:] 							#.replace('0'*bytesLabel,'')
	for key, value in paths.items():
		if key.startswith(srcIP):

	 		
			#To print all telemetry values uncomment the following 5 commented lines			
			#print(key, value, len(value.replace(' ',''))//bytesLabel)
			#if not intType: print(key, pathshop[key]) 
			rkey=revKey(key)
			#print(rkey, paths[rkey], len(value.replace(' ',''))//bytesLabel)
			#if not intType: print(rkey, pathshop[rkey]) 
			#print('')
			
			dstPath=paths[key].replace(' ','')
			dstHops=pathshop[key].replace(' ','')
		
			genOccurrancies = [dstPath.count(rightDst[x]) for x in range(0,len(rightDst),bytesLabel)]         #List with number of occurancies for every path swID
			
			#----------- Calculate Paths --------------------			
			#List of all swIds of rightDst and altDst 
			pathids = [rightDst[i:i+bytesLabel] for i in range(0,len(rightDst),bytesLabel)]
			altids = [altDst[i:i+bytesLabel] for i in range(0,len(altDst),bytesLabel)]
			
			if len(dstPath)!=len(dstHops): print('Hops out of Sync----------')
			if len(dstPath)//bytesLabel!=len(timestamps[key]): print('-*-*-*-*-*-*-*-TimeStamp sequence out of sync!')
			remainingDstPath = '' #dstPath
			countRightPaths = 0 					#Collection of swIDs that form a path
			rightPathPresent=False
			pathUpdate=False
			for i in range(0,len(dstPath),bytesLabel):
				swid=dstPath[i:i+bytesLabel]
				swHop=dstHops[i:i+bytesLabel] #The corresponding hop number for swid
				#nodeStr+=swid #+'('+swHop[1]+')'
				#print(pathids,swid,swHop,rightDstHop[rightDst.find(swid):rightDst.find(swid)+bytesLabel])
				if swid in pathids and swHop==rightDstHop[rightDst.find(swid):rightDst.find(swid)+bytesLabel]:	
					pathids.remove(swid)
					#remainingDstPath = remainingDstPath[:j]+remainingDstPath[j+bytesLabel:]			#Remove swID
				else:
					#j+=bytesLabel
					remainingDstPath+=swid
				if swid in altids and swHop==altDstHop[altDst.find(swid):altDst.find(swid)+bytesLabel]:
					altids.remove(swid)
				if not pathids:
					#nodeStr+='('+str(len(nodeStr[nodeStr.rfind('\n'):])//bytesLabel)+')\n'
					countRightPaths+=1
					pathids = [rightDst[i:i+bytesLabel] for i in range(0,len(rightDst),bytesLabel)] #Initialize pathids
					altids = [altDst[i:i+bytesLabel] for i in range(0,len(altDst),bytesLabel)]			#Initialize altids
					#lastRemaining = remainingDstPath
					rightPathPresent=True
				if rightPathPresent and not pathUpdate and not altids and key.find('.9000')==-1:
					#nodeStr+='('+str(len(nodeStr[nodeStr.rfind('\n'):])//bytesLabel)+')~\n'
					currentTS=timestamps[key][i//bytesLabel]
					timeLapse=interval(minPUtimestamp,currentTS)
					#print(len(dstPath)-i)
					sumTimeLapse+=timeLapse
					print('TimeLapse= '+str(timeLapse))
					pathUpdate=True
				
			#print(nodeStr)
			#print('-------')
			if pathUpdate==True: altPath+=1

			totAccurate+=countRightPaths
			#print(len(dstPath)//len(rightDst),countRightPaths)
			totInaccurate+=len(dstPath)//len(rightDst)-countRightPaths

			if (len(remainingDstPath)//bytesLabel>len(rightDst[bytesLabel:])):		#If remaining is more than a path's length
					totRemaining+=len(remainingDstPath)//bytesLabel

			#Calculate lost Labels (ie swIDs)	
			foundLabels=countRightPaths*len(rightDst)//bytesLabel
			occurrancies = [remainingDstPath.count(rightDst[x:x+bytesLabel]) for x in range(0,len(rightDst),bytesLabel)]         #List with number of occurancies for every path swID
			minimum = min(occurrancies)
			foundLabels+=minimum*len(rightDst)//bytesLabel									#Labels that form paths but unordered
			occurrancies = [x-minimum for x in occurrancies]		#Orphan swIds
			shouldBe=sum(occurrancies)//((len(rightDst)//bytesLabel))					#Num of paths if they were accurate
			lostLabels=0																				#lostLabes = swIds that do not form paths
			for item in occurrancies:
				if item<shouldBe:
					lostLabels+=shouldBe-item
					foundLabels+=item
				else:
					foundLabels+=shouldBe

			if lostLabels<len(rightDst)//bytesLabel: lostLabels=0

			totFoundLabels+=foundLabels
			totLostLabels+=lostLabels
				

timeLapses.sort()
if len(timeLapses)>0:
	if len(timeLapses)%2==0:
			median=timeLapses[len(timeLapses)//2-1]+timeLapses[len(timeLapses)//2]
	else:
		median=timeLapses[len(timeLapses)//2]
else:
	median=0
print('Path= '+str(rightDst)+' Alt Path= '+str(altDst))
print('Accurate= '+str(totAccurate))
print('Inaccurate= '+str(totInaccurate))
print('Total foundLabels= '+str(totFoundLabels))
print('Total lostLabels= '+str(totLostLabels))
print('Total Lost Reset= '+str(totLostReset))
print('Path Update detected by= '+str(altPath))
#print('Path Update Unordered detected by= '+str(altPathUn))
if altPath!=0: print('Average PU time lapse= '+str(round(sumTimeLapse/altPath)))
print('Median PU time lapse= '+str(median))
print('Total flows= '+str(round(len(paths.keys())/2)))
print('Total packets= '+str(numOfPackets))
print('Total INT packets= '+str(numOfINT))
print('Total Duplicates= '+str(totDuplicates))
print('Valuable INT packets= '+str(valuableINT))
print('Extra INT packets= '+str(extraINT))
print('Total Redundant= '+str(totRemaining))

