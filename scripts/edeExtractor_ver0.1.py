#edeExtractor.py

from sys import argv

script, filename = argv

txt = open(filename)

print "Reading file %r:" % filename

flag = False
keywordMap = dict()

for line in txt:

	print "--> %s <--\n" %line
	
	if(line[0] == '#'):	
		
		resources = line.split(";")

		index = 0
		while(len(resources) > 0):		
			
			keywordMap[resources.pop(0)] = index
			index = index + 1

		flag = True; 
		
	if(flag):

		resources = line.split(";")
		
		#print resources[keywordMap["object-name"]]
		#print "Do something"

		if(len(resources) > keywordMap["object-type"] and len(resources) > keywordMap["object-instance"]):

			if(len(resources) > keywordMap["min-present-value"] and resources[keywordMap["min-present-value"]] != "" and len(resources) > keywordMap["max-present-value"] and resources[keywordMap["max-present-value"]]):

				resources[keywordMap["min-present-value"]] = resources[keywordMap["min-present-value"]].replace(",",".");
				resources[keywordMap["max-present-value"]] = resources[keywordMap["max-present-value"]].replace(",",".");

				print "if(currentBacAdd in addresses && object$id == BACnetAPDUTypes::BACnetObjectType[%s] && object$instance == %s && property == \"present-value\"){if(to_double(val) < %s || to_double(val) > %s){flag = T;}}\n" % (resources[keywordMap["object-type"]], resources[keywordMap["object-instance"]], resources[keywordMap["min-present-value"]], resources[keywordMap["max-present-value"]])
		
			elif(len(resources) > keywordMap["min-present-value"] and resources[keywordMap["min-present-value"]] != ""):

				resources[keywordMap["min-present-value"]] = resources[keywordMap["min-present-value"]].replace(",",".");
		
				print "if(currentBacAdd in addresses && object$id == BACnetAPDUTypes::BACnetObjectType[%s] && object$instance == %s && property == \"present-value\"){if(to_double(val) < %s){flag = T;}}\n" % (resources[keywordMap["object-type"]], resources[keywordMap["object-instance"]], resources[keywordMap["min-present-value"]])

			elif(len(resources) > keywordMap["max-present-value"] and resources[keywordMap["max-present-value"]] != ""):

				resources[keywordMap["max-present-value"]] = resources[keywordMap["max-present-value"]].replace(",",".");
		
				print "if(currentBacAdd in addresses && object$id == BACnetAPDUTypes::BACnetObjectType[%s] && object$instance == %s && property == \"present-value\"){to_double(val) > %s){flag = T;}}\n" % (resources[keywordMap["object-type"]], resources[keywordMap["object-instance"]], resources[keywordMap["max-present-value"]])


	#else:
		#print "Nothing to do..."

#print keywordMap



