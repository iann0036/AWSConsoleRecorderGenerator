import os
import json
import pprint
import math

services = None
occurances = []

with open("combined.json", "r") as f:
    services = json.loads(f.read())

with open("bg.js", "r") as f:
    lines = f.read().splitlines()
    for line in lines:
        line = line.strip()
        if (line.startswith("// autogen:") or line.startswith("// manual:")):
            lineparts = line.split(":")
            occurances.append(lineparts[2])

total_services = 0
total_operations = 0
total_unique_occurances = 0
with open("coverage.md", "w") as f:
    f.write("## Service Coverage\n\n")
    f.write("| Service | Coverage |\n")
    f.write("| --- | --- |\n")

    for servicename in sorted(services):
        service = services[servicename]
        occurance_count = 0
        for operation in service['operations']:
            if servicename + "." + operation['name'] in occurances:
                occurance_count += 1
        if occurance_count > 0:
            coverage_val = "%s/%s (%s%%)" % (occurance_count, len(service['operations']), math.floor(occurance_count * 100 / len(service['operations'])))
            f.write("| *%s* | %s |\n" % (servicename, coverage_val))
    
    f.write("\n## Operation Coverage\n\n")
    f.write("| Service | Operation | Occurances |\n")
    f.write("| --- | --- | --- |\n")
    for servicename in sorted(services):
        service = services[servicename]
        total_services += 1
        for operation in service['operations']:
            total_operations += 1
            occurance_count = occurances.count(servicename + "." + operation['name'])
            if occurance_count > 0:
                total_unique_occurances += 1
            f.write("| *%s* | `%s` | %s |\n" % (servicename, operation['name'], occurance_count))

    f.write("\n\n**Total Services: %s**\n\n**Total Operations: %s**\n\n**Total Unique Occurances: %s**\n"
        % (total_services, total_operations, total_unique_occurances)
    )
