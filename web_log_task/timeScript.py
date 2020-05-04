#!/bin/python3

from datetime import datetime

file = open('dmp.txt', 'r')

timestamps = []
timeleft = []
counter = 1
bits = ""
password = ""


for line in file:
  timestamps.append(line[30:38]) #Get timestamps

file.close()


for time in range(len(timestamps)):
  #print(timestamps[time])
  if time + 1 < len(timestamps):
    timeleft.append(datetime.strptime(timestamps[time + 1], '%H:%M:%S') - datetime.strptime(timestamps[time], '%H:%M:%S')) #Compare time1 with time2 and save time differ
    #print(timeleft[time])

for time in range(len(timestamps)):
  if counter % 4 == 1 or counter % 4 == 2 or counter % 4 == 3: #The two biter
    if time + 1 < len(timestamps):
      if str(timeleft[time]) == '0:00:00':
        print(timestamps[time])
        bits += '00'
        print('x00')
      if str(timeleft[time]) == '0:00:02':
        print(timestamps[time])
        bits += '01'
        print('x01')
      if str(timeleft[time]) == '0:00:04':
        print(timestamps[time])
        bits += '10'
        print('x10')
      if str(timeleft[time]) == '0:00:06':
        print(timestamps[time])
        bits = bits + '11'
        print('x11')

  elif counter % 4 == 0:  #The one biter
    if time + 1 < len(timestamps):
      if str(timeleft[time]) == '0:00:02':
        print(timestamps[time])
        bits += '0'
        print('x0')
      if str(timeleft[time]) == '0:00:04':
        print(timestamps[time])
        bits += '1'
        print('x1')
      
      print(bits)
      password +=(chr(int(bits, 2))) #Translate Bits to ASSCI
      bits = ''
  counter = counter+1

print(password)





