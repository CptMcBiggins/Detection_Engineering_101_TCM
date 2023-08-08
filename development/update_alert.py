import requests
import os
import tomllib

api_key = os.environ['ELASTIC_KEY']
url = 'https://detectionengineering101-1f562a.kb.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules'
headers = {'Authorization': 'ApiKey '+api_key, 'kbn-xsrf': 'true','Content-Type': 'application/json'}

changed_files = os.environ["CHANGED_FILES"]

for root, dirs, files in os.walk("detections/"):
	for file in files:
		if file in changed_files:
			data = "{\n"
			if file.endswith('.toml'):
				full_path = os.path.join(root, file)
				with open(full_path, "rb") as toml:
					alert = tomllib.load(toml)
				if alert['rule']['type'] == 'query':
					required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','threat']
				elif alert['rule']['type'] == 'eql':
					required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','language','threat']
				elif alert['rule']['type'] == 'threshold':
					required_fields = ['author','description','name','rule_id','risk_score','severity','type','query','threshold','threat']
				else:
					print('Unsupported Rule Type found in: ' + full_path)
					break

				for field in alert['rule']:
					if field in required_fields:
						if type(alert['rule'][field]) == list:
							data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
						elif type(alert['rule'][field]) == str:
							if field == 'description':
								data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"").replace("\\", "\\\\") + "\"," + "\n"
							elif field == 'query':
								data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\\","\\\\ ").replace("\"","\\\"").replace("\n"," ") + "\"," + "\n"
							else:
								data += "  " + "\"" + field + "\": \"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"") + "\"," + "\n"
						elif type(alert['rule'][field]) == int:
							data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
						elif type(alert['rule'][field]) == dict:
							data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
				data += "  \"enabled\": true\n}"

			rule_id = alert['rule']['rule_id']
			url = url + "?rule_id=" + rule_id
			elastic_data = requests.put(url, headers=headers, data=data).json()
			print(elastic_data)