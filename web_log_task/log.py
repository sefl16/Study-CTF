from urllib import unquote
from datetime import datetime
 
f = open('dmp.txt', 'r')
 
def get_date(line):
        dateField = line[3]
        date = dateField[1:len(dateField)]
        return datetime.strptime(date, '%d/%b/%Y:%H:%M:%S')
 
prev_date = False
counter = 0
result = ''
letters = []
 
for line in f:
    if len(line):
        data = line.split(' ')
 
        if prev_date is not False:
            delta = (get_date(data) - prev_date).seconds
            counter += 1
 
            # every 4th request there is last bit checked
            if counter % 4:
                if delta == 0:
                    result += '00'
                elif delta == 2:
                    result += '01'
                elif delta == 4:
                    result += '10'
                elif delta == 6:
                    result += '11'
            else:
                if delta == 2:
                    result += '0'
                elif delta == 4:
                    result += '1'
                else:
                    # no last bit found
                    pass
 
                letters.append(result)
                result = ''
 
        prev_date = get_date(data)
 
f.close()
 
pwd = ''
for letter in letters:
    pwd += chr(int(letter, 2))
 
print pwd

