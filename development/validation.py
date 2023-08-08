#! bin/bash/env python3

import tomllib
import sys
import os

failure = 0

for root, dirs, files in os.walk("detections/"):
	for file in files:
		if file.endswith('.toml'):
			full_path = os.path.join(root, file)
			with open(full_path, "rb") as toml:
				alert = tomllib.load(toml)

				present_fields = []
				missing_fields = []

				try:
					if alert['metadata']['creation_date']:
						pass
				except:
					print("The Metadata table does not contain a creation_date on: " + full_path)

				if alert['rule']['type'] == 'query':
					required_fields = ['description','name','rule_id','risk_score','severity','type','query']
				elif alert['rule']['type'] == 'eql':
					required_fields = ['description','name','rule_id','risk_score','severity','type','query','language']
				elif alert['rule']['type'] == 'threshold':
					required_fields = ['description','name','rule_id','risk_score','severity','type','query','threshold']
				else:
					print('Unsupported Rule Type found in: ' + full_path)
					break

				for table in alert:
					for field in alert[table]:
						present_fields.append(field)

				for field in required_fields:
					if field not in present_fields:
						missing_fields.append(field)

				if missing_fields:
					print("The following fields do not exist in " + file + ": "+ str(missing_fields))
					failure = 1
				else:
					print("Validation Passed for: " + file)

if failure != 0:
	sys.exit(1)