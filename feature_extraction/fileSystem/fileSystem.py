import json

data = json.load(open('report.json'))

generic=data["behavior"]["generic"]
dropped=data["dropped"]

topExt=['bak', 'bat', 'bmp', 'cfg', 'clb', 'com', 'vbs', 'dat', 'db',
'dll', 'doc', 'docx', 'exe', 'ico', 'ime', 'inf', 'ini', 'jpeg',
'jpg', 'js', 'lnk', 'log', 'otf', 'pdf', 'pnf', 'png', 'reg',
'rtf', 'sav', 'sys', 'tmp', 'txt', 'xls', 'xlsx', 'xml','docm','ps1','psc1','psm1']
topPt= ['C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs','C:\\ProgramData',
'C:\\Users\\Malware\\AppData\\Local\\Temp','C:\\Users\\Malware\\AppData\\Local',
'C:\\Users\\Malware\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs','C:\\Users\\Malware\\AppData\\Roaming','C:\\Users\\Malware',
'C:\\Program Files\\Common Files','C:\\Program Files','C:\\$Recycle.Bin','C:\\Windows\\System32\\drivers','C:\\Windows\\System32','C:\\Windows']
fileTypes=['file','directory','drivers','ADS','pipe']
fileSize=['0-64', '65-4096', '4097-262144','262144+']

numberOfFilesDeleted=0
numberOfFilesModified=0
numberOfFilesCreated=0
numberOfFilesRead=0
numberOfFilesAccessed=0

deletedDistinctPath=0
deletedDistinctExt=0
modifiedDistinctPath=0
modifiedDistinctExt=0
createdDistinctPath=0
createdDistinctExt=0

pathsDeleted = []
extensionsDeleted = []
pathsModified = []
extensionsModified = []
pathsCreated = []
extensionsCreated = []
fileSizeFreq = [0]*4

topExtensionsDeleted = dict.fromkeys(topExt,0)
topPathsDeleted = dict.fromkeys(topPt,0)
topExtensionsModified = dict.fromkeys(topExt,0)
topPathsModified = dict.fromkeys(topPt,0)
fileTypesModified = dict.fromkeys(fileTypes,0)
topExtensionsCreated = dict.fromkeys(topExt,0)
topPathsCreated = dict.fromkeys(topPt,0)
fileTypesAccessed = dict.fromkeys(fileTypes,0)
fileTypesRead = dict.fromkeys(fileTypes,0)

for x in generic:
	if len(x["summary"])>0:
		if "file_deleted" in x["summary"]:
			numberOfFilesDeleted = numberOfFilesDeleted + len(x["summary"]["file_deleted"])
			for k in x["summary"]["file_deleted"]:
				pathsDeleted.append('\\'.join(k.split('\\')[0:-1]))				
				extensionsDeleted.append(k.split('.')[-1])
		if "file_written" in x["summary"]:
			numberOfFilesModified = numberOfFilesModified + len(x["summary"]["file_written"])
			for k in x["summary"]["file_written"]:
				pathsModified.append('\\'.join(k.split('\\')[0:-1]))
				ext = k.split('.')[-1]
				extensionsModified.append(ext)
				if ext=="sys":
					fileTypesModified['drivers'] = fileTypesModified['drivers'] + 1
				elif ':' in k.split('\\')[-1]:
					fileTypesModified['ADS'] = fileTypesModified['ADS'] + 1
				elif "\\\\.\\" in k:
					fileTypesModified['pipe'] = fileTypesModified['pipe'] + 1
				else:
					fileTypesModified['file'] = fileTypesModified['file'] + 1
		if "file_created" in x["summary"]:
			numberOfFilesCreated = numberOfFilesCreated + len(x["summary"]["file_created"])
			for k in x["summary"]["file_created"]:
				pathsCreated.append('\\'.join(k.split('\\')[0:-1]))
				extensionsCreated.append(k.split('.')[-1])
		if "file_read" in x["summary"]:
			numberOfFilesRead = numberOfFilesRead + len(x["summary"]["file_read"])
			for k in x["summary"]["file_read"]:
				ext = k.split('.')[-1]
				if ext=="sys":
					fileTypesRead['drivers'] = fileTypesRead['drivers'] + 1
				elif ':' in k.split('\\')[-1]:
					fileTypesRead['ADS'] = fileTypesRead['ADS'] + 1
				elif "\\\\.\\" in k:
					fileTypesRead['pipe'] = fileTypesRead['pipe'] + 1
				else:
					fileTypesRead['file'] = fileTypesRead['file'] + 1
		if "file_opened" in x["summary"]:
			numberOfFilesAccessed = numberOfFilesAccessed + len(x["summary"]["file_opened"])
			for k in x["summary"]["file_opened"]:
				ext = k.split('.')[-1]
				if len(k.split('.'))==1:
					fileTypesAccessed['directory'] = fileTypesAccessed['directory'] + 1
				elif ext=="sys":
					fileTypesAccessed['drivers'] = fileTypesAccessed['drivers'] + 1
				elif ':' in k.split('\\')[-1]:
					fileTypesAccessed['ADS'] = fileTypesAccessed['ADS'] + 1
				elif "\\\\.\\" in k:
					fileTypesAccessed['pipe'] = fileTypesAccessed['pipe'] + 1
				else:
					fileTypesAccessed['file'] = fileTypesAccessed['file'] + 1
			
for x in dropped:
	if x["size"]>=0 and x["size"]<65:
		fileSizeFreq[0] = fileSizeFreq[0] + 1
	elif x["size"]>=65 and x["size"]<4097:
		fileSizeFreq[1] = fileSizeFreq[1] + 1
	elif x["size"]>=4097 and x["size"]<262145:
		fileSizeFreq[2] = fileSizeFreq[2] + 1
	elif x["size"]>=262145:
		fileSizeFreq[3] = fileSizeFreq[3] + 1
	 	
deletedDistinctPath = len(set(pathsDeleted))
deletedDistinctExt = len(set(extensionsDeleted))

modifiedDistinctPath = len(set(pathsModified))
modifiedDistinctExt = len(set(extensionsModified))

createdDistinctPath = len(set(pathsCreated))
createdDistinctExt = len(set(extensionsCreated))

for key in topExtensionsDeleted:
	topExtensionsDeleted[key]=extensionsDeleted.count(key)
for x in pathsDeleted:
	for key in topPt:
		if key in x :
			topPathsDeleted[key] = topPathsDeleted[key] +1
			break
for key in topExtensionsModified:
	topExtensionsModified[key]=extensionsModified.count(key)
for x in pathsModified:
	for key in topPt:
		if key in x :
			topPathsModified[key] = topPathsModified[key] +1
			break
for key in topExtensionsCreated:
	topExtensionsCreated[key]=extensionsCreated.count(key)
for x in pathsCreated:
	for key in topPt:
		if key in x :
			topPathsCreated[key] = topPathsCreated[key] +1
			break	


