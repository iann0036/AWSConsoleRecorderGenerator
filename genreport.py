import os
import json
import pprint
import math
import re

services = None
cfn_spec = None
occurances = []
skipped_ops = []
tf_resources = []
cfn_types = []
cfn_occurances = [
    "AWS::CloudFormation::CustomResource",
    "AWS::CloudFormation::WaitCondition",
    "AWS::CloudFormation::WaitConditionHandle",
    "AWS::SDB::Domain",
    "AWS::EC2::SecurityGroupEgress",
    "AWS::EC2::SecurityGroupIngress",
    "AWS::Redshift::ClusterSecurityGroup",
    "AWS::Redshift::ClusterSecurityGroupIngress",
    "AWS::ServiceDiscovery::PrivateDnsNamespace",
    "AWS::ServiceDiscovery::PublicDnsNamespace",
    "AWS::ServiceDiscovery::Service",
    "AWS::ServiceDiscovery::Instance",
    "AWS::SecretsManager::SecretTargetAttachment",
    "AWS::SecretsManager::ResourcePolicy",
    "AWS::RDS::DBSecurityGroup",
    "AWS::RDS::DBSecurityGroupIngress",
    "AWS::ElastiCache::SecurityGroup",
    "AWS::ElastiCache::SecurityGroupIngress",
    "Alexa::ASK::Skill",
    "AWS::EC2::EC2Fleet",
    "AWS::Kinesis::StreamConsumer"
]
tf_occurances = []

with open("combined.json", "r") as f:
    services = json.loads(f.read())

with open("cfnspec.json", "r") as f:
    cfn_spec = json.loads(f.read())['ResourceTypes']

with open("tf_resources.txt", "r") as f:
    lines = f.read().splitlines()
    for line in lines:
        tf_resources.append(line)

for cfntype, _ in cfn_spec.items():
    cfn_types.append(cfntype)

with open("bg.js", "r") as f:
    text = f.read()
    lines = text.splitlines()
    cfn_occurances += re.compile('(AWS\:\:[a-zA-Z0-9]+\:\:[a-zA-Z0-9]+)').findall(text)
    tf_occurances += re.compile('terraformType\'\:\ \'(aws(?:\_[a-zA-Z0-9]+)+)\'').findall(text)
    for line in lines:
        line = line.strip()
        if line.startswith("// autogen:") or line.startswith("// manual:"):
            lineparts = line.split(":")
            occurances.append(lineparts[2])

with open("skipped.txt", "r") as f:
    lines = f.read().splitlines()
    for line in lines:
        skipped_ops.append(line)

total_services = 0
total_operations = 0
total_unique_occurances = 0
with open("coverage.md", "w") as f:
    f.write("## CloudFormation Resource Coverage\n\n")
    f.write("**%s/%s (%s%%)** Resources Covered\n" % (
        len(set(cfn_occurances)),
        len(cfn_types),
        math.floor(len(set(cfn_occurances)) * 100 / len(cfn_types))
    ))

    f.write("\n| Type | Coverage |\n")
    f.write("| --- | --- |\n")

    for cfntype in sorted(cfn_types):
        f.write("| *%s* | %s |\n" % (cfntype, cfn_occurances.count(cfntype)))

    f.write("\n## Terraform Coverage\n\n")
    f.write("**%s/%s (%s%%)** Resources Covered\n" % (
        len(set(tf_occurances)),
        len(tf_resources),
        math.floor(len(set(tf_occurances)) * 100 / len(tf_resources))
    ))
    
    f.write("\n| Type | Coverage |\n")
    f.write("| --- | --- |\n")

    for tf_resource in sorted(tf_resources):
        f.write("| *%s* | %s |\n" % (tf_resource, tf_occurances.count(tf_resource)))

    f.write("\n## Service Coverage\n\n")
    f.write("| Service | Coverage |\n")
    f.write("| --- | --- |\n")

    for servicename in sorted(services):
        service = services[servicename]
        occurance_count = 0
        for operation in service['operations']:
            if servicename + "." + operation['name'] in occurances or servicename + "." + operation['name'] in skipped_ops:
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

    f.write("\n\n**Total Services: %s**\n\n**Total Operations: %s**\n\n**Total Unique Occurances: %s (%s%%)**\n"
        % (total_services, total_operations, total_unique_occurances, (math.floor(total_unique_occurances * 100 / total_operations)))
    )
