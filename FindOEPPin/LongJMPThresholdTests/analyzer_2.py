import re
import sys

entry_point = "00401220" # we know this a priori 
ep_index = -1
#lenght of the oep jump
delta_jmp_oep = -1
#total number of jumps
number_jmps = 0
#jumps longer than the oep -1 because we don't want to include the jump to the oep itself
jmps_greater_oep = -1

scale = 0.01 #scale factor to divide the write-sets size
classes = []
counter_list = [0] * 100 # 1 to 1 correspondence with the classes ( they are always 100 ) 

unique_write_set_index = []


def generate_classes(fraction,size):
	
	cont = 0
	classes.append([cont,int(fraction)])
	cont = 1

	acc = int(fraction)
	acc = acc + fraction
	
	if acc == 0:
		fraction = 1
		acc = 1
	
	size = int(fraction * 1/scale)
	#print "size is" + str(size)
	
	while acc < size:

		classes.append([cont,int(acc)])
		acc = acc + int(fraction)
		cont = cont + 1

	classes.append([cont,int(acc)])

	#print classes
	#print "LEN OF CLASSES " + str(len(classes))
	

def insert_in_classes(delta_jmp,fraction,oep_flag):
    
	global ep_index

	index_calculated = delta_jmp // fraction
	#print "Index calculated is " + str(index_calculated)
	if index_calculated >= 1/scale:
		index_calculated = 1/scale-1

	counter_list[int(index_calculated)] += 1
	if oep_flag == 1:
		ep_index = index_calculated

	#print "THE FIRST CLASS IS :" + str(classes[0][1]) +"\n"
	#print "----------PUTTED " + str(delta_jmp) + " IN CLASS" + str(int(index_calculated)) + "------------\n"



# ENTRY POINT			

if len(sys.argv) != 3:
	print "analyzer_2.py <input_file> <output_file>"
	sys.exit(0)
  	
try:
	
	in_file = open(sys.argv[1],"r")
	out_file = open(sys.argv[2],"w")
except IOError:
	print "Files not found"
	sys.exit(0)

  


# parse the unique write set indexes in the file 
for line in in_file:
	splitted = line.strip().split(",") 
	if len(splitted) < 4: # last element is garbage 
		continue
	wtis = splitted[3].strip()[17:]
	wsize = splitted[4].strip()[21:]

	witem_info = [wtis,wsize]
	if witem_info not in unique_write_set_index:
		unique_write_set_index.append(witem_info)

#print str(unique_write_set_index) + "\n"

for witem in unique_write_set_index:

	in_file.seek(0)
	size = int(witem[1],10) # get the size from the witem 
	index = witem[0] # get the index
	fraction = int(size * scale)

	generate_classes(fraction,size)

	#print classes 

	for line in in_file:
    		number_jmps += 1
		splitted = line.strip().split(",") 
		#print splitted
		if len(splitted) < 4: # last element is garbage 
			continue
		wtis = splitted[3].strip()[17:]
		oep = splitted[1].strip()[11:]

		if index == wtis: # if the current analyzed long jump is in the current write set analyzed 
			delta_jmp = int(splitted[2].strip()[12:],10)
			#print delta_jmp
			if oep == entry_point:
        			delta_jmp_oep = delta_jmp
				insert_in_classes(delta_jmp,fraction,1)
			else:
				insert_in_classes(delta_jmp,fraction,0)

	#print "\n"
	#print counter_list
	#print "\n"


	k=0
  	oep_set = str(-1)+"/100"
	#print "EIP INDEX"  + str(ep_index)
	for c in classes:
		#print k
		#print c[0]
		#print "eip " + str(ep_index)
		#print "c[0]" + str(c[0])
		#set the oep_set to the index class which contains the oep
		if str(c[0]) == str(int(ep_index)): 
                        oep_set = str(int(c[0])+1) +"/100"
		#track how many jumps greater than the oep jump there are 
		if ep_index != -1 and c[0] >=  ep_index:
			jmps_greater_oep += counter_list[k]
		out_file.write(str(int(c[0])+1) +"/100 : " + str(counter_list[k]) + "\n")

		k = k+1


	out_file.write("Write set size: " + str(size) + "\n")
  	out_file.write("Oep set: "+oep_set+"\n")
 	out_file.write("Total number jumps: "+str(number_jmps)+"\n")
  	out_file.write("Oep jump lenght: "+str(delta_jmp_oep)+"\n")
	out_file.write("Number of jumps longer than the oep jump: "+str(jmps_greater_oep)+" "+str(jmps_greater_oep*100/float(number_jmps))+"%"+"\n")

	out_file.write("---\n\n")
	counter_list = [0] * 101
	classes = []
	ep_index = -1


