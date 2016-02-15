#picsSearch.py

from sys import argv

script, filename = argv

txt = open(filename)

print "Reading file %r" % filename
#print txt.read()

s = set();

for line in txt:
	resources = line.split("\t")
	if(len(resources) == 3):
		s.add(resources[1])
		#print resources[1]

#print s;

import urllib2

def getgoogleurl(search,siteurl=False):
    if siteurl==False:
        return 'http://www.google.com/search?q='+urllib2.quote(search)
    else:
        return 'http://www.google.com/search?q=site:'+urllib2.quote(siteurl)+'%20'+urllib2.quote(search)

def getgooglelinks(search,siteurl=False):
   #google returns 403 without user agent
   headers = {'User-agent':'chrome'}
   req = urllib2.Request(getgoogleurl(search,siteurl),None,headers)
   site = urllib2.urlopen(req)
   data = site.read()
   site.close()

   #no beatifulsoup because google html is generated with javascript
   start = data.find('<div id="res">')
   end = data.find('<div id="foot">')
   if data[start:end]=='':
      #error, no links to find
      return False
   else:
      links =[]
      data = data[start:end]
      start = 0
      end = 0       
      while start>-1 and end>-1:
          #get only results of the provided site
          if siteurl==False:
            start = data.find('<a href="/url?q=')
          else:
            start = data.find('<a href="/url?q='+str(siteurl))
          data = data[start+len('<a href="/url?q='):]
          end = data.find('&amp;sa=U&amp;')
          if start>-1 and end>-1: 
              link =  urllib2.unquote(data[0:end])
              data = data[end:len(data)]
              if link.find('http')==0:
                  links.append(link)
      return links

# links = getgooglelinks('BACnet PICS HX 80E', 'http://www.bacnetinternational.net/')
# for link in links:
#	print link

def download_file(download_url, name):
    response = urllib2.urlopen(download_url)
    file = open(name, 'w')
    file.write(response.read())
    file.close()
    print("Completed")

import httplib2
from BeautifulSoup import BeautifulSoup, SoupStrainer

for bacs_information in s:

	downloadedlinks = set()

	pics_information = "PICS " + bacs_information

	print "Searching for \"%s\"" %(pics_information)

	links = getgooglelinks(pics_information, 'http://www.bacnetinternational.net/')

	num = int(0)
	for link in links:
		
		if link not in downloadedlinks and ("pdf" in link or "PDF" in link):

			downloadedlinks.add(link)

			file_name = (bacs_information + "_" + str(num) + ".pdf").replace(" ","_")
			num = num + 1

			url = link;
    			print "Downloading %s" %(url)
    			download_file(url, file_name)

	links = getgooglelinks("bacnet" + pics_information)
	
	for link in links:
		
		if link not in downloadedlinks and ("pdf" in link or "PDF" in link):

			downloadedlinks.add(link)

			file_name = (bacs_information + "_" + str(num) + ".pdf").replace(" ","_")
			num = num + 1

			url = link;
    			print "Downloading %s" %(url)
    			download_file(url, file_name)

	links = getgooglelinks(pics_information)
	
	for link in links:
		
		if link not in downloadedlinks and ("pdf" in link or "PDF" in link):

			downloadedlinks.add(link)

			file_name = (bacs_information + "_" + str(num) + ".pdf").replace(" ","_")
			num = num + 1

			url = link;
    			print "Downloading %s" %(url)
    			download_file(url, file_name)






