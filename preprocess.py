import os
import json
import pprint

def getServiceContent(service):
    service_versions = os.listdir("botocore/botocore/data/%s" % service)
    service_versions.sort() # sort lexicographically
    latest_service_version = service_versions.pop()
    service_files = os.listdir("botocore/botocore/data/%s/%s" % (service, latest_service_version))
    for service_file in service_files:
        if "service-" in service_file:
            with open("botocore/botocore/data/%s/%s/%s" % (service, latest_service_version, service_file)) as f:  
                contents = f.read()
                return json.loads(contents)

services = os.listdir("botocore/botocore/data")

services_output = {}

for service in services:
    if "." in service:
        continue

    operations = []

    service_content = getServiceContent(service)
    for _, operation_params in service_content['operations'].iteritems():
        operation_inputs = []
        operation_outputs = []
        if 'input' in operation_params:
            input_shape_name = operation_params['input']['shape']
            for member, _ in service_content['shapes'][input_shape_name]['members'].iteritems():
                operation_inputs.append(member)
        if 'output' in operation_params:
            output_shape_name = operation_params['output']['shape']
            for member, _ in service_content['shapes'][output_shape_name]['members'].iteritems():
                operation_outputs.append(member)
        operations.append({
            'name': operation_params['name'],
            'inputs': operation_inputs,
            'outputs': operation_outputs
        })
    
    services_output[service] = {
        'operations': operations
    }

with open("combined.json", "w") as f:  
    f.write(json.dumps(services_output))