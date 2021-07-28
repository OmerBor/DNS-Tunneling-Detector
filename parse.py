from datetime import datetime, timedelta
import os
import json
import heapq
import time

dates = [
	('2min', timedelta(minutes = 2)),
	('10min', timedelta(minutes = 10)),
	('30min', timedelta(minutes = 30)),
    ('1Hr', timedelta(hours = 1)),
    ('2Hr', timedelta(hours = 2)),
    ('4Hr', timedelta(hours = 4)),
    ('12Hr', timedelta(hours = 12)),
    ('1 Day', timedelta(days = 1)),
    ('2 Days', timedelta(days = 2)),
    ('1 Week', timedelta(weeks = 1)),
    ('1 Month', timedelta(weeks = 4)),
	('6 Month', timedelta(weeks = 24))
]	

FMT = "%Y %b %d %H:%M:%S"

def GetShortenedVersionForSus(domain):
	"""
	Counts both XXXXX.a.com and YYYYYYY.a.com towards counts for
	a.com. If the domain is suspicious, takes the ending xxx.yyy 
	as it is and adds other subdomains to the string if they are
	short enough.

	Parameters
	----------
	domain : str
		A string representing the name of the domain.

	Returns
	-------
	str
		A string representing the shortned domain.
	"""

	tokensList = domain.rsplit(".", 5)
	strout = ""
	num = 0
	
	for token in reversed(tokensList):
		if num > 1 and len(token) > 10:
			break
		strout = "." + token + strout
		num += 1

	if strout.find(".") == 0:
		strout = strout[1:]

	return "<...>" + strout


class LOG:
	"""
	A class used to represent a DNS log.

	Attributes
	----------
	date : str
		A string representing the date of the log.
	domain : str
		A string representing the domain name.
	isSuspiciousDomain : bool
			A boolean flag indicating whether a log's domain is considerd suspicious(default is False).
	count : int
		An integer representing the number of queries for the corresponding domain(default is 1).
	"""

	def __init__(self, date, domain, isSuspiciousDomain = False, count = 1):
		"""
		Parameters
		----------
		date : str
			A string representing the date of the log.
		domain : str
			A string representing the domain name.
		isSuspiciousDomain : bool
			A boolean flag indicating whether a log's domain is considerd suspicious(default is False).
		count : int
			An integer representing the number of queries for the corresponding domain(default is 1).
		"""

		self.date = date
		self.domain = domain
		self.isSuspiciousDomain = isSuspiciousDomain
		self.count = count


	def __str__(self):

		domain = getShortendVersion(self.domain)

		return domain + "\nTime of peak:\n" + self.date.strftime(FMT) + "\ncount(10min):\n" + str(self.count)


class MyEncoder(json.JSONEncoder):
	"""
	A class used to subclass JSONEncoder in order to implement a custom serialization.

	Methods
	-------
	default(obj)
		Serializes the object passed as a parameter. 
	"""
	
	def default(self, obj):
		"""
		Serializes the object passed as a parameter in a custom manner.
		If the object is not an instance of classes LOG or datetime, it will be serialized
		by JSONEncoder's default method. 

		Parameters
		----------
		obj : object
			An object to be serialized.

		Returns
		-------
		dictionary
			The serialization of the given object.
		"""

		if isinstance(obj, LOG): 
			return { "date" : obj.date.strftime(FMT), "domain": obj.domain, "count": obj.count}
		elif isinstance(obj, datetime): 
			return { "date" : obj.strftime(FMT)}
		return json.JSONEncoder.default(self, obj)
		

#class Object:        #####should be deleted?
    #def toJSON(self):
        #return json.dumps(self, default=lambda o: o.__dict__, 
            #sort_keys=True, indent=4)

		
class DATABASE:
	"""
	A class used to represent the database of the logs being parsed.

	Attributes
	----------
	logs : dict
		A dictionary used to store logs being parsed(default is empty dictionary).
	numberOfLogs : int
		An integer representing the number of logs in the database(default is 0).
	numbersOfDomains : dict
		A dictionary used to store domains of logs being parsed(default is empty dictionary).
	countForDomains : dict
		A dictionary used to store the number of queries per domain(default is empty dictionary).
	heapCount : lst
		An auxiliary list used to store domains and adequate number of queries in a heap(default is empty list).
	heap10Span : lst
		An auxiliary list used to store domains and adequate number of queries, of a 10 minutes 
		time span in a heap(default is empty list).
	offsetInLogFile : int 
		An integer representing the current file position of the logs file(default is 0).
	chosenDateSpan : int
		An integer representing an index into dates structure(default is 2).
	dateToLook : str
		A string representing the date of the logs we are interested in.
	blockedList : lst
		A list of the domains considered suspicious(default is empty list).
	blockedListTemp : lst
		An auxiliary list of domains considered suspicious(default is empty list).
	approvedList : lst
		A list of domains approved by the user(default is empty list).
	terminated : bool
		A boolean indicating whether the parser is still active.

	Methods
	-------
	AddDomain(number, domain)
		Inserts value number(passed as a parameter) at key domain(passed as a parameter) in numberOfDomains attribute.
	ListToLogs(data)
		Creates a list of logs from data passed as a parameter.
	ConvertDataToLogs(data)
		Fills in the logs attribute according to data passed as a parameter.
	MyConverter(data)
		An auxiliary method for the gui.py module.
	CheckAndUpdateCounter(entry, log)
		Checks whether the log is within a 10 minutes time span.
	IncTimeSpan()
		An auxiliary method fot the gui.py module.
	DecTimeSpan()
		An auxiliary method for the gui.py module.
	SetMinTimeSpan()
		An auxiliary method fot the gui.py module.
	GetSpanString()
		An auxiliary method for the gui.py module.
	GetHistoryOfDomain(domain)
		An auxiliary method for the gui.py module.
	UpdateFileBlocked()
		Automatically blocks suspicious domains. 
	AddToApprovedList(domain)
		An auxiliary method for the gui.py module.
	AddToBlockedList(domain)
		A method that inserts a domain into the blockedList attribute.
	RemoveFromApprovedList(domain)
		An auxiliary method for the gui.py module.
	RemoveFromBlockedList(domain)
		An auxiliary method for the gui.py module.
	GetBlockedList()
		A getter method for the blockedList attribute.
	GetApprovedList()
		A getter method for the approvedList attribute.
	SetDateToLook(date)
		A setter method for the dateToLook attribute.
	GetDateToLook()
		A getter method for the dateToLook attribute.
	ResetDateToLook()
		A method for resetting the dateToLook attribute.
	GetSpanTime()
		A method that retrieves a dates structure entry.
	AddToDatabase(log)
		A method that adds a log to the database.
	FindHighestKElements(k)
		A method that finds the highest given k elements in the heapCount attribute.
	FindHighestKElements10Min(k)
		A method that finds the highest given k elements in the heap10Span attribute.
	CountNumberOfUniqueCharacters(domain)
		A method that counts the number of unique characters in given domain name.
	CountNumberOfDigitsInDomainName(domain)
		A method that counts the number of digits in given domain name.
	FetchEntryOfDomain(domain)
		A method that fetches the corresponding logs attribute entry if present.
	Terminate()
		A method that sets the terminated attribute to True.
	ParseIntoLog(date, domain)
		A method that creates a LOG instance, given date and domain.
	Parse(fileName)
		A method that parses a logs file.
	"""

	def __init__(self):

		self.logs = {}
		self.numberOfLogs = 0
		self.numbersOfDomains = {}
		self.countForDomains = {}
		self.heapCount = []
		self.heap10Span = []
		self.offsetInLogFile = 0
		self.chosenDateSpan = 2
		self.dateToLook = datetime.now()
		self.blockedList = []
		self.blockedListTemp = []
		self.approvedList = []
		self.terminated = False
	

	def AddDomain(self, number, domain):
		"""
		Inserts value number(passed as a parameter) at key domain(passed as a parameter) in numberOfDomains attribute.

		Parameters
		----------
		number : int
			An integer representing the current number of domains.
		domain : str
			A string representing the name of the domain to be inserted.
		"""

		self.numbersOfDomains[domain] = number

	
	def ListToLogs(self, data):
		"""
		Creates a list of logs from data passed as a parameter.

		Parameters
		----------
		data : lst
			A list of logs strings.

		Returns
		-------
		lst
			A list of LOGs instances.
		"""

		lst = []

		for mapString in data:
			lst.append(LOG(datetime.strptime(mapString["date"], FMT), mapString["domain"], count = mapString["count"]))

		return lst

		
	def ConvertDataToLogs(self, data):
		"""
		Fills in the logs attribute according to data passed as a parameter.

		Parameters
		----------
		data : lst
			A list of strings representing logs that were parsed.
		"""

		for key, listOfLogString in data.items():
			self.logs[int(key)] = self.ListToLogs(listOfLogString)
			
	
	def MyConverter(self, data):
		"""
		An auxiliary method for the gui.py module, that converts data passed as a parameter
		and fills the various attributes accordingly.

		Parameters
		----------
		data : JSON str
			A JSON string representing data parsed from the logs file.
		"""

		if not data["logs"]:
			self.offsetInLogFile = 0
			return

		self.ConvertDataToLogs(data["logs"])
		self.numberOfLogs = data["numberOfLogs"]
		self.numbersOfDomains = data["numbersOfDomains"]
		self.countForDomains = data["countForDomains"]
		self.offsetInLogFile = data["offsetInLogFile"]
		self.chosenDateSpan = data["chosenDateSpan"]
		self.blockedList = data["blockedList"]
		self.approvedList = data["approvedList"]
		

	#def isSameDomain(self, domain1, domain2):   #####Ask whether it's been used.
		##n2=domain2[:domain2.rfind('.')].rfind('.')
		#suf1=domain1[domain1.rfind('.'):]
		#suf2=domain2[domain2.rfind('.'):]
		#if suf1 == suf2:
			#if(domain1[n1:]==domain2[n2:]):
				#return True
		#return False
		
	#def getShortendDomain2Dots(self, domain):    #####Ask whether it's been used.
		#n1=domain[:domain.rfind('.')].rfind('.')
		#return domain[n1:]

	
	def CheckAndUpdateCounter(self, entry, log):
		"""
		Checks whether the log is within a 10 minutes time span, 
		thus count(LOG attribute) should be updated.

		Parameters
		----------
		entry : LOG
			A LOG instance corresponding to the domain request being examined
			(belongs to logs attribute).
		log : LOG
			A LOG instance representing the most recent log of a corresponding domain.
		"""
		
		if log.date - entry[0].date  < timedelta(minutes = 10):
			entry[0].count += 1
		if log.isSuspiciousDomain and log.date - entry[0].date  < timedelta(minutes = 10):
			if entry[0].count > 20:
				self.AddToBlockedList(log.domain)
		elif log.date - entry[0].date  < timedelta(minutes = 10):
				if(entry[0].count > 500):
					self.AddToBlockedList(log.domain)
		else :
			entry.insert(0, log)


	def IncTimeSpan(self):
		"""
		An auxiliary method fot the gui.py module, that increases
		the time span to focus on.

		Returns
		-------
		bool
			A boolean respresenting whether the operation was successful.
		"""

		output = False

		if self.chosenDateSpan < len(dates) - 1:
			self.chosenDateSpan += 1
			output = True

		return output


	def DecTimeSpan(self):
		"""
		An auxiliary method for the gui.py module, that decreases 
		the time span to focus on.

		Returns
		-------
		bool
			A boolean respresenting whether the operation was successful.
		"""

		output = False

		if self.chosenDateSpan > 0:
			self.chosenDateSpan -= 1
			output = True

		return output

	
	def SetMinTimeSpan(self):
		"""
		An auxiliary method fot the gui.py module, that resets 
		the chosenDateSpan attribute.
		"""
		self.chosenDateSpan = 0


	def GetSpanString(self):
		"""
		An auxiliary method for the gui.py module, that returns 
		a string representation of a dates structure entry.

		Returns
		-------
		str
			A string representing a time span.
		"""

		return dates[self.chosenDateSpan][0]


	def GetHistoryOfDomain(self, domain):
		"""
		An auxiliary method for the gui.py module, that returns 
		an adequate logs attribute entry.

		Parameters
		----------
		domain : str
			A string representing a domain name.

		Returns
		-------
		LOG
			A LOG instance corresponding to given domain name.
		"""

		return self.FetchEntryOfDomain(domain)

	
	def UpdateFileBlocked(self):
		"""
		Automatically blocks suspicious domains. 
		"""

		blockedDomainList = ""

		for domain in self.blockedListTemp:
			if domain.find("<...>") != -1:
				domain = domain[5:]
				os.system('sudo /home/os212/pygui/updateBlock.sh %s' %domain)
			else:
				blockedDomainList += "5.145.145.0 " + domain + ".\n"
		with open('/home/os212/pygui/dnsmasq.hosts', 'w') as hostsFile:
			hostsFile.write(blockedDomainList)
			hostsFile.close()
		os.system('sudo /home/os212/pygui/reloadConf.sh')


	def AddToApprovedList(self, domain):
		"""
		An auxiliary method for the gui.py module, that inserts 
		a domain into the approvedList attribute.

		Parameters
		----------
		domain : str
			A string representing a domain name to be added to
			the approvedList attribute.
		"""

		if domain not in self.blockedList:
			if domain not in self.approvedList:
				self.approvedList.append(domain)


	def AddToBlockedList(self, domain):
		"""
		A method that inserts a domain into the blockedList attribute.

		Parameters
		----------
		domain : str
			A string representing a domain name to be added to
			the blockedList attribute.
		"""

		if domain not in self.approvedList: 
			if domain not in self.blockedList:
				self.blockedList.append(domain)
				self.blockedListTemp.append(domain)
				self.UpdateFileBlocked()
				

	def RemoveFromApprovedList(self, domain):
		"""
		An auxiliary method for the gui.py module, that removes 
		a domain from the approvedList attribute if present.

		Parameters
		----------
		domain : str
			A string representing a domain name to be removed
			from the approvedList attribute.
		"""

		if domain in self.approvedList:
			self.approvedList.remove(domain)


	def RemoveFromBlockedList(self, domain):
		"""
		An auxiliary method for the gui.py module, that removes 
		a domain from the blockedList attribute if present.

		Parameters
		----------
		domain : str
			A string representing a domain name to be removed
			from the blockedList attribute.
		"""

		if domain in self.blockedList:
			self.blockedList.remove(domain)
			self.UpdateFileBlocked()


	def GetBlockedList(self):
		"""
		A getter method for the blockedList attribute.

		Returns
		-------
		lst
			A list of domain names(strings) representing the
			blockedList attribute.
		"""

		return self.blockedList


	def GetApprovedList(self):
		"""
		A getter method for the approvedList attribute.

		Returns
		-------
		lst
			A list of domain names(strings) representing the
			approvedList attribute.
		"""

		return self.approvedList

		
	def SetDateToLook(self, date):
		"""
		A setter method for the dateToLook attribute.

		Parameters
		----------
		date : str
			A string representing a date to be set.
		"""

		date = datetime.strptime(date, FMT)
		self.dateToLook = date


	def GetDateToLook(self):
		"""
		A getter method for the dateToLook attribute.

		Returns
		-------
		str
			A string representing the dateToLook attribute.
		"""

		return self.dateToLook


	def ResetDateToLook(self):
		"""
		A method for resetting the dateToLook attribute.
		"""

		self.dateToLook = datetime.now()


	def GetSpanTime(self):
		"""
		A method that retrieves a dates structure entry.

		Returns
		-------
		str
			A string representing a date.
		"""

		return dates[self.chosenDateSpan][1]


	def AddToDatabase(self, log):
		"""
		A method that adds a log to the database.

		Parameters
		----------
		log : LOG
			A LOG instance representing a log that was parsed
			from the logs file.
		"""

		shortendDomain = log.domain
		entry = self.FetchEntryOfDomain(shortendDomain)
		
		if entry == None:
			self.logs[self.numberOfLogs] = [log]
			self.AddDomain(self.numberOfLogs, shortendDomain)
			self.countForDomains[shortendDomain] = 1
			self.numberOfLogs += 1
		else:
			self.CheckAndUpdateCounter(entry, log)
			self.countForDomains[shortendDomain] += 1


	def FindHighestKElements(self, k):
		"""
		A method that finds the highest given k elements in 
		the heapCount attribute.

		Parameters
		----------
		k : int
			An integer representing the number of highest
			elements to be found.

		Returns
		-------
		lst
			A list representing the given k highest elements.
		"""

		self.heapCount = []

		for loglist in self.logs.values():
			count = 0
			domain = loglist[0].domain
			for log in loglist:
				if abs(self.dateToLook - log.date) < self.GetSpanTime():
					count += log.count
			if count > 0:
				heapq.heappush(self.heapCount, (count, domain))

		return heapq.nlargest(k, self.heapCount)


	def FindHighestKElements10Min(self, k):
		"""
		A method that finds the highest given k elements in 
		the heap10Span attribute.

		Parameters
		----------
		k : int
			An integer representing the number of highest
			elements to be found.

		Returns
		-------
		lst
			A list representing the given k highest elements.
		"""

		self.heap10Span = []
		
		for loglist in self.logs.values():
			for log in loglist:
				if abs(self.dateToLook - log.date) < self.GetSpanTime():
					heapq.heappush(self.heap10Span, (log.count, str(log), log))
					
		return heapq.nlargest(k, self.heap10Span)


	def CountNumberOfUniqueCharacters(self, domain):
		"""
		A method that counts the number of unique characters 
		in given domain name.

		Parameters
		----------
		domain : str
			A string representing a domain name.

		Returns
		-------
		int
			An integer representing the number of unique characters
			in given domain name.
		"""

		differentCharacters = {}

		for character in domain:
			if not character in differentCharacters:
				differentCharacters[character] = 1

		return len(differentCharacters)


	def CountNumberOfDigitsInDomainName(self, domain):
		"""
		A method that counts the number of digits in given domain name.

		Parameters
		----------
		domain : str
			A string representing a domain name.

		Returns
		-------
		int 
			An integer representing the number of digits in given
			domain name.
		"""

		numberOfDigits = 0

		for character in domain:
			if character >= '0' and character <= '9':
				numberOfDigits += 1

		return numberOfDigits

	
	def FetchEntryOfDomain(self, domain):
		"""
		A method that fetches the corresponding logs attribute entry 
		if present.

		Parameters
		----------
		domain : str
			A string representing a domain name.

		Returns
		-------
		LOG
			A corresponding LOG instance if present, otherwise None
			is returned.
		"""

		output = None

		if domain in self.numbersOfDomains:
			output = self.logs[self.numbersOfDomains[domain]]
			
		return output


	def Terminate(self):
		"""
		A method that sets the terminated attribute to True.
		"""
		
		self.terminated = True


	def ParseIntoLog(self, date, domain):
		"""
		A method that creates a LOG instance, given date and domain.
		The method checks whether the domain name is considered
		suspicious as well, and if so sets the isSuspiciousDomain
		attribute(LOG) to True.

		Parameters
		----------
		date : str
			A string representing a date.
		domain : str
			A string representing a domain name.

		Returns
		-------
		LOG
			A LOG instance corresponding to the given parameters.
		"""

		date = datetime.strptime("2021 " + date, FMT)
		log = LOG(date, domain)
		
		if len(domain) > 52 or self.CountNumberOfUniqueCharacters(domain) > 27 or self.CountNumberOfDigitsInDomainName(domain) > 7:
			log = LOG(date, GetShortenedVersionForSus(domain))
			log.isSuspiciousDomain = True
			
		return log


	def Parse(self, fileName):
		"""
		A method that parses a logs file.

		Parameters
		----------
		fileName : str
			A string representing a logs file name.
		"""

		with open(fileName, "r") as fh:
			if self.offsetInLogFile != 0:
				fh.seek(self.offsetInLogFile)
			for line in fh:
				tokensList = line.split(None, 4)
				try:
					if len(tokensList[1]) < 2: 
						date = tokensList[0] + " 0" + tokensList[1] + " " + tokensList[2]
					else:
						date = tokensList[0] + " " + tokensList[1] + " " + tokensList[2]
					content = tokensList[4].split(" ")
					if content[0] == 'query[A]' or content[0] == 'query[AAAA]' or content[0] == 'query[TXT]' or content[0] == 'query[MX]':
						log = self.ParseIntoLog(date, content[1])
						self.AddToDatabase(log)
				except:
					if tokensList != []:
						print("failed: " + line)
				
			self.offsetInLogFile = fh.tell()
			
			while True:
				if not self.terminated:
					try:
						self.offsetInLogFile = fh.tell()
						line = fh.readline()
						if not line:
							time.sleep(1)
							fh.seek(self.offsetInLogFile)
						else:
							print(line) 
							tokensList = line.split(None, 4)
							try:
								if len(tokensList[1]) < 2: 
									date = tokensList[0] + " 0" + tokensList[1] + " " + tokensList[2]
								else:
									date = tokensList[0] + " " + tokensList[1] + " " + tokensList[2]
								content = tokensList[4].split(" ")
								if content[0] == 'query[A]' or content[0] == 'query[AAAA]' or content[0] == 'query[TXT]':
									log = self.ParseIntoLog(date, content[1])
									self.AddToDatabase(log)
							except:
								print("failed parsing line: " + line)
				
					except:
						print("problem reading file in thread")
						exit(1)
				else:
					print("Thread Exiting")
					exit(0)

			
def main():
	
	database = DATABASE()
	while True:
		command = input("Enter Command to continue...\n")
		if command != "":
			if command == "parse":
				database.Parse("dnsmasq.log")
			if command == "show":
				print(database.FindHighestKElements(2))
				print(database.FindHighestKElements10Min(2))
			if command == "print data":
				database.printAllLogs()
	

if __name__ == "__main__":
    main() 