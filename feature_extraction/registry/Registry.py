import json

def has_key(_dict,key):
	if key in _dict.keys():
		return True
	else:
		return False


keys = ["regkey_written","regkey_read","regkey_opened","regkey_accessed"]

class RegistryFeatures():
	def __init__(self,report_path):
		self.report_path = report_path
		self.data = self.read_data()
		self.extracted_data = {"regkey_written":[],
		                       "regkey_read":[],
		                       "regkey_opened":[],
		                       "regkey_accessed":[]}

		
		#normal count
		self.number_of_features = {"regkey_written" : 0,
		                                  "regkey_read" : 0,
		                                  "regkey_opened" : 0,
		                                  "regkey_accessed" : 0}
	
	def read_data(self):
		return json.load(open(self.report_path))
	
	def extract_features(self):
		generic = self.data["behavior"]["generic"]
		for i in generic:
			summary = i["summary"]
			for key in keys:
				if has_key(summary,key):
					self.extracted_data[key].extend(summary[key])
		self.count_feauteres()
	
	def count_feauteres(self):
		for key in keys:
			self.number_of_features[key] = len(self.extracted_data[key])
	
	def show_features(self):
		print "Number of features"
		for key in keys:
			print key + ": " + str(self.number_of_features[key])

if __name__ == "__main__":
	path = "/home/frkn/Desktop/malwy/reports/Reports/reports4/report.json"
	rf = RegistryFeatures(path)
	rf.extract_features()
	rf.show_features()