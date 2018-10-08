var combined = null;
var requests_with_potentials = [];

chrome.runtime.onMessage.addListener(
    function(message, sender, sendResponse) {
        if (message.action == "getRequests") {
            sendResponse(requests_with_potentials);
        }
        if (message.action == "getCombined") {
            sendResponse(combined);
        }
    }
);

chrome.browserAction.onClicked.addListener(
    function(){
        chrome.tabs.create({
            url: chrome.extension.getURL("main.html")
        });
    }
);

chrome.webRequest.onBeforeRequest.addListener(
    logRequest,
    {urls: ["<all_urls>"]},
    ["requestBody","blocking"]
);

fetch("combined.json")
  .then(response => response.json())
  .then(json => combined = json);

function escapeRegExp(str) {
    return str.replace(/[.*+?^${}\/()|[\]\\]/g, '\\$&'); // $& means the whole matched string
}

function deplural(str) {
    if (str === null)
        return "";
    if (str.endsWith("s")) {
        return str.substring(0, str.length - 1);
    }
    if (str.endsWith("ies")) {
        return str.substring(0, str.length - 3);
    }
    return str;
}

function logRequest(details) {
    var requestBody = null;
    var jsonRequestBody = null;

    if (details.type != "xmlhttprequest") return;

    if (analyseRequest(details) === true) return;

    try {
        requestBody = decodeURIComponent(String.fromCharCode.apply(null, new Uint8Array(details.requestBody.raw[0].bytes)));
        jsonRequestBody = JSON.parse(requestBody);
    } catch(e) {;}

    var rgx = /^.*console\.aws\.amazon\.com\/([a-zA-Z0-9-]+)\/(.+)$/g;
    var match = rgx.exec(details.url);

    if (match && match.length > 2) {
        var service = match[1];
        var pathending = match[2];

        if (pathending === null) {
            pathending = "";
        }
        if (requestBody === null) {
            requestBody = "";
        }

        var valid_service = false;
        for (var i in combined) {
            if (service == combined[i]['endpoint_prefix']) {
                valid_service = true;
            }
        }

        if (valid_service) {
            var potentials = [];
            console.log(details.url);
            for (var testing_service in combined) {
                for (var operation in combined[testing_service]['operations']) {
                    // Dedup here

                    var operation_name = deplural(combined[testing_service]['operations'][operation]['name']).toLowerCase();
                    if (pathending.toLowerCase().includes(operation_name) || pathending.toLowerCase().replace("get", "describe").includes(operation_name)) {
                        console.log("Potential Match: " + testing_service + "." + combined[testing_service]['operations'][operation]['name']);
                        potentials.push({
                            'service': testing_service,
                            'opid': operation,
                            'opname': combined[testing_service]['operations'][operation]['name'],
                            'foundinuri': true
                        });
                    } else if (requestBody.toLowerCase().includes(operation_name) || requestBody.toLowerCase().replace("get", "describe").includes(operation_name)) {
                        console.log("Potential Match: " + testing_service + "." + combined[testing_service]['operations'][operation]['name']);
                        potentials.push({
                            'service': testing_service,
                            'opid': operation,
                            'opname': combined[testing_service]['operations'][operation]['name'],
                            'foundinuri': false
                        });
                    }
                }
            }

            var regex = '.+' + escapeRegExp(`console.aws.amazon.com/${service}/${pathending}`) + '$'; ///
            
            requests_with_potentials.push({
                'url': details.url,
                'method': details.method,
                'potentials': potentials,
                'service': service,
                'requestBody': requestBody,
                'regex': regex
            });
            console.warn("---");
        }
    }
}

/********/

var outputs = [];
var tracked_resources = [];
var blocking = false;

function analyseRequest(details) {
    var reqParams = {
        'boto3': {},
        'go': {},
        'cfn': {},
        'cli': {}
    };
    var requestBody = null;
    var jsonRequestBody = null;
    var region = 'us-west-2';

    try {
        requestBody = decodeURIComponent(String.fromCharCode.apply(null, new Uint8Array(details.requestBody.raw[0].bytes)));
        jsonRequestBody = JSON.parse(requestBody);
    } catch(e) {;}

    //--CloudFormation--//

    if (details.method == "GET" && details.url.match(/.+console\.aws\.amazon\.com\/cloudformation\/service\/stacks\?/g)) {
        console.log("TODO - CFN");
    }

    //--EC2--//
    
    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getMergedInstanceList\?/g)) {
        if ('filters' in jsonRequestBody) {
            reqParams.cli['--filters'] = jsonRequestBody.filters;
            reqParams.boto3['Filter'] = [];
            jsonRequestBody['filters'].forEach(filter => {
                reqParams.boto3['Filter'].push({
                    'Name': filter['name'],
                    'Values': filter['values']
                });
            });
        }
        reqParams.boto3['MaxResults'] = jsonRequestBody.count;

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeInstances',
                'boto3': 'describe_instances',
                'cli': 'describe-instances'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getPrivateImageList\?/g)) {
        if (jsonRequestBody['publicAndPrivate'] != true) {
            reqParams.boto3['Owner'] = ['self'];
            reqParams.cli['--owners'] = "self";
        }

        if ('imageType' in jsonRequestBody) {
            if (jsonRequestBody['filters'] === undefined)
                jsonRequestBody['filters'] = [];
            jsonRequestBody.filters['imageType'] = jsonRequestBody.imageType;
        }
        
        if ('filters' in jsonRequestBody) {
            reqParams.cli['--filters'] = jsonRequestBody.filters;
            reqParams.boto3['Filter'] = [];
            jsonRequestBody['filters'].forEach(filter => {
                reqParams.boto3['Filter'].push({
                    'Name': filter['name'],
                    'Values': filter['values']
                });
            });
        }
        reqParams.boto3['MaxResults'] = jsonRequestBody.count;

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeImages',
                'boto3': 'describe_images',
                'cli': 'describe-images'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=searchAmis\?/g)) {
        reqParams.boto3['MaxResults'] = jsonRequestBody.count;
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeImages',
                'boto3': 'describe_images',
                'cli': 'describe-images'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getVpcs\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeVpcs',
                'boto3': 'describe_vpcs',
                'cli': 'describe-vpcs'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getSubnets\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeSubnets',
                'boto3': 'describe_subnets',
                'cli': 'describe-subnets'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getSdkResources_Hosts\?/g)) {
        if ('filters' in jsonRequestBody) {
            reqParams.cli['--filters'] = jsonRequestBody.filters;
            reqParams.boto3['Filter'] = [];
            jsonRequestBody['filters'].forEach(filter => {
                reqParams.boto3['Filter'].push({
                    'Name': filter['name'],
                    'Values': filter['values']
                });
            });
        }

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeHosts',
                'boto3': 'describe_hosts',
                'cli': 'describe-hosts'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getInstanceProfileList\?/g)) {
        outputs.push({
            'region': region,
            'service': 'iam',
            'method': {
                'api': 'ListInstanceProfiles',
                'boto3': 'list_instance_profiles',
                'cli': 'list-instance-profiles'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getNetworkInterfaces\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeNetworkInterfaces',
                'boto3': 'describe_network_interfaces',
                'cli': 'describe-network-interfaces'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getAvailabilityZones\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeAvailabilityZones',
                'boto3': 'describe_availability_zones',
                'cli': 'describe-availability-zones'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getSecurityGroups\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeSecurityGroups',
                'boto3': 'describe_security_groups',
                'cli': 'describe-security-groups'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getKeyPairList\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeKeyPairs',
                'boto3': 'describe_key_pairs',
                'cli': 'describe-key-pairs'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=createSecurityGroup\?/g)) {
        reqParams.boto3['GroupDescription'] = jsonRequestBody.groupDescription;
        reqParams.boto3['GroupName'] = jsonRequestBody.groupName;
        reqParams.cli['--description'] = jsonRequestBody.groupDescription;
        reqParams.cli['--group-name'] = jsonRequestBody.groupName;
        reqParams.cfn['GroupDescription'] = jsonRequestBody.groupDescription;
        reqParams.cfn['GroupName'] = jsonRequestBody.groupName;
        if ('vpcId' in jsonRequestBody) {
            reqParams.boto3['VpcId'] = jsonRequestBody.vpcId;
            reqParams.cli['--vpc-id'] = jsonRequestBody.vpcId;
            reqParams.cfn['VpcId'] = jsonRequestBody.vpcId;
        }

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'CreateSecurityGroup',
                'boto3': 'create_security_group',
                'cli': 'create-security-group'
            },
            'options': reqParams,
            'was_blocked': blocking
        });

        tracked_resources.push({
            'region': region,
            'service': 'ec2',
            'type': 'AWS::EC2::SecurityGroup',
            'options': reqParams,
            'was_blocked': blocking
        });

        if (blocking) {
            notifyBlocked();
            return {cancel: true};
        }

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=authorizeIngress\?/g)) {
        if ('groupId' in jsonRequestBody) {
            reqParams.boto3['GroupId'] = jsonRequestBody.groupId;
            reqParams.cli['--group-id'] = jsonRequestBody.groupId;
        }
        reqParams.boto3['IpPermissions'] = [];
        reqParams.cli['--ip-permissions'] = [];
        jsonRequestBody['ipPermissions'].forEach(ipPermission => {
            var ipRangeObjects = [];
            ipPermission['ipRangeObjects'].forEach(ipRangeObject => {
                ipRangeObjects.push({
                    'Description': ipRangeObject['description'],
                    'CidrIp': ipRangeObject['cidrIp']
                });
            });
            var ipv6RangeObjects = [];
            ipPermission['ipv6RangeObjects'].forEach(ipv6RangeObject => {
                ipv6RangeObjects.push({
                    'Description': ipv6RangeObject['description'],
                    'CidrIpv6': ipv6RangeObject['CidrIpv6']
                });
            });
            reqParams.boto3['IpPermissions'].push({
                'IpProtocol': ipPermission['ipProtocol'],
                'FromPort': ipPermission['fromPort'],
                'ToPort': ipPermission['toPort'],
                'IpRanges': ipRangeObjects,
                'Ipv6Ranges': ipv6RangeObjects
            });
            reqParams.cli['--ip-permissions'].push({
                'IpProtocol': ipPermission['ipProtocol'],
                'FromPort': ipPermission['fromPort'],
                'ToPort': ipPermission['toPort'],
                'IpRanges': ipRangeObjects,
                'Ipv6Ranges': ipv6RangeObjects
            });
        });

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'AuthorizeSecurityGroupIngress',
                'boto3': 'authorize_security_group_ingress',
                'cli': 'authorize-security-group-ingress'
            },
            'options': reqParams,
            'was_blocked': blocking
        });

        if (blocking) {
            notifyBlocked();
            return {cancel: true};
        }

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\/elastic\/\?call\=com.amazonaws.ec2.AmazonEC2.RunInstances\?/g)) {
        reqParams.boto3['ImageId'] = jsonRequestBody.ImageId;
        reqParams.boto3['MaxCount'] = jsonRequestBody.MaxCount;
        reqParams.boto3['MinCount'] = jsonRequestBody.MinCount;
        reqParams.boto3['KeyName'] = jsonRequestBody.KeyName;
        reqParams.boto3['SecurityGroupId'] = jsonRequestBody.SecurityGroupIds;
        reqParams.boto3['InstanceType'] = jsonRequestBody.InstanceType;
        reqParams.boto3['Placement'] = jsonRequestBody.Placement;
        reqParams.boto3['Monitoring'] = jsonRequestBody.Monitoring;
        reqParams.boto3['DisableApiTermination'] = jsonRequestBody.DisableApiTermination;
        reqParams.boto3['InstanceInitiatedShutdownBehavior'] = jsonRequestBody.InstanceInitiatedShutdownBehavior;
        reqParams.boto3['CreditSpecification'] = jsonRequestBody.CreditSpecification;
        reqParams.boto3['TagSpecification'] = jsonRequestBody.TagSpecifications;
        reqParams.boto3['EbsOptimized'] = jsonRequestBody.EbsOptimized;
        reqParams.boto3['BlockDeviceMapping'] = jsonRequestBody.BlockDeviceMappings;

        reqParams.cfn['ImageId'] = jsonRequestBody.ImageId;
        reqParams.cfn['MaxCount'] = jsonRequestBody.MaxCount;
        reqParams.cfn['MinCount'] = jsonRequestBody.MinCount;
        reqParams.cfn['KeyName'] = jsonRequestBody.KeyName;
        reqParams.cfn['SecurityGroupId'] = jsonRequestBody.SecurityGroupIds;
        reqParams.cfn['InstanceType'] = jsonRequestBody.InstanceType;
        reqParams.cfn['Placement'] = jsonRequestBody.Placement;
        reqParams.cfn['Monitoring'] = jsonRequestBody.Monitoring;
        reqParams.cfn['DisableApiTermination'] = jsonRequestBody.DisableApiTermination;
        reqParams.cfn['InstanceInitiatedShutdownBehavior'] = jsonRequestBody.InstanceInitiatedShutdownBehavior;
        reqParams.cfn['CreditSpecification'] = jsonRequestBody.CreditSpecification;
        reqParams.cfn['TagSpecification'] = jsonRequestBody.TagSpecifications;
        reqParams.cfn['EbsOptimized'] = jsonRequestBody.EbsOptimized;
        reqParams.cfn['BlockDeviceMapping'] = jsonRequestBody.BlockDeviceMappings;

        reqParams.cli['--image-id'] = jsonRequestBody.ImageId;
        if (jsonRequestBody.MaxCount == jsonRequestBody.MinCount) {
            reqParams.cli['--count'] = jsonRequestBody.MinCount;
        } else {
            reqParams.cli['--count'] = jsonRequestBody.MinCount + ":" + jsonRequestBody.MaxCount;
        }
        reqParams.cli['--key-name'] = jsonRequestBody.KeyName;
        reqParams.cli['--security-group-ids'] = jsonRequestBody.SecurityGroupIds;
        reqParams.cli['--instance-type'] = jsonRequestBody.InstanceType;
        reqParams.cli['--placement'] = jsonRequestBody.Placement;
        reqParams.cli['--monitoring'] = jsonRequestBody.Monitoring;
        if (jsonRequestBody.DisableApiTermination === true)
            reqParams.cli['--disable-api-termination'] = null;
        else if (jsonRequestBody.DisableApiTermination === false)
            reqParams.cli['--enable-api-termination'] = null;
        reqParams.cli['--instance-initiated-shutdown-behavior'] = jsonRequestBody.InstanceInitiatedShutdownBehavior;
        reqParams.cli['--credit-specification'] = jsonRequestBody.CreditSpecification;
        reqParams.cli['--tag-specifications'] = jsonRequestBody.TagSpecifications;

        if (jsonRequestBody.EbsOptimized === true)
            reqParams.cli['--ebs-optimized'] = null;
        else if (jsonRequestBody.EbsOptimized === false)
            reqParams.cli['--no-ebs-optimized'] = null;
        reqParams.cli['--block-device-mappings'] = jsonRequestBody.BlockDeviceMappings;

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'RunInstances',
                'boto3': 'run_instances',
                'cli': 'run-instances'
            },
            'options': reqParams,
            'was_blocked': blocking
        });

        tracked_resources.push({
            'region': region,
            'service': 'ec2',
            'type': 'AWS::EC2::Instance',
            'options': reqParams,
            'was_blocked': blocking
        });

        if (blocking) {
            notifyBlocked();
            return {cancel: true};
        }

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=terminateInstances\?/g)) {
        reqParams.boto3['InstanceIds'] = jsonRequestBody.instanceIds;
        reqParams.cli['--instance-ids'] = jsonRequestBody.instanceIds;

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'TerminateInstances',
                'boto3': 'terminate_instances',
                'cli': 'terminate-instances'
            },
            'options': reqParams,
            'was_blocked': blocking
        });

        if (blocking) {
            notifyBlocked();
            return {cancel: true};
        }

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\/elastic\/\?call\=com.amazonaws.ec2.AmazonEC2.DescribeLaunchTemplates\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeLaunchTemplates',
                'boto3': 'describe_launch_templates',
                'cli': 'describe-launch-templates'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\/elastic\/\?call\=com.amazonaws.directoryservice.+.DescribeDirectories\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ds',
            'method': {
                'api': 'DescribeDirectories',
                'boto3': 'describe_directories',
                'cli': 'describe-directories'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\/elastic\/\?call\=com.amazonaws.ec2.AmazonEC2.DescribePlacementGroups\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribePlacementGroups',
                'boto3': 'describe_placement_groups',
                'cli': 'describe-placement-groups'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getCurrentSpotPrice\?/g)) {
        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeSpotPriceHistory',
                'boto3': 'describe_spot_price_history',
                'cli': 'describe-spot-price-history'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getTags\?/g)) {
        reqParams.boto3['Filter'] = [];
        reqParams.cli['--filter'] = [];

        if (jsonRequestBody['key']) {
            if (jsonRequestBody['key'].length > 0) {
                reqParams.boto3['Filter'].push({
                    'Name': 'key',
                    'Values': [jsonRequestBody['key']]
                });
                reqParams.cli['--filter'].push({
                    'Name': 'key',
                    'Values': [jsonRequestBody['key']]
                });
            }
        }
        if (jsonRequestBody['value']) {
            if (jsonRequestBody['value'].length > 0) {
                reqParams.boto3['Filter'].push({
                    'Name': 'value',
                    'Values': [jsonRequestBody['value']]
                });
                reqParams.cli['--filter'].push({
                    'Name': 'value',
                    'Values': [jsonRequestBody['value']]
                });
            }
        }
        if (reqParams.boto3['Filter'].length == 0) {
            delete reqParams.boto3['Filter'];
            delete reqParams.cli['--filter'];
        }

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeTags',
                'boto3': 'describe_tags',
                'cli': 'describe-tags'
            },
            'options': reqParams
        });

        return true;
    }

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/ec2\/ecb\?call\=getTerminationProtection\?/g)) {
        reqParams.boto3['InstanceId'] = jsonRequestBody.instanceId;
        reqParams.boto3['Attribute'] = "disableApiTermination";
        reqParams.cli['--instance-id'] = jsonRequestBody.instanceId;
        reqParams.cli['--attribute'] = "disableApiTermination";

        outputs.push({
            'region': region,
            'service': 'ec2',
            'method': {
                'api': 'DescribeInstanceAttribute',
                'boto3': 'describe_instance_attribute',
                'cli': 'describe-instance-attribute'
            },
            'options': reqParams
        });

        return true;
    }

    //--S3--//

    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/s3\/proxy/g)) {
        if (jsonRequestBody.operation == "ListObjects") {
            reqParams.boto3['BucketName'] = jsonRequestBody.path;
            reqParams.boto3['Prefix'] = jsonRequestBody.params.prefix;
            reqParams.cli['_'] = [
                `s3://${jsonRequestBody.path}/${jsonRequestBody.params.prefix}`
            ]

            outputs.push({
                'region': region,
                'service': 's3',
                'method': {
                    'api': 'ListObjects',
                    'boto3': 'list_objects',
                    'cli': 'ls'
                },
                'options': reqParams
            });
        }

        return true;
    }

    /* Start Auto */

    // medialive
    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/medialive\/api\/inputs/g)) {
        outputs.push({
            'region': region,
            'service': 'medialive',
            'method': {
                'api': 'ListInputs',
                'boto3': 'list_inputs',
                'cli': 'list-inputs'
            },
            'options': reqParams
        });

        return true;
    }
    
    // guardduty
    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/guardduty\/api\/guardduty$/g) && jsonRequestBody.operation == "ListDetectors") {
        outputs.push({
            'region': region,
            'service': 'guardduty',
            'method': {
                'api': 'ListDetectors',
                'boto3': 'list_detectors',
                'cli': 'list-detectors'
            },
            'options': reqParams
        });
        
        return true;
    }

    // config
    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/config\/service\/aggregationAuthorization\/describePendingAggregationRequests\?/g)) {
        outputs.push({
            'region': region,
            'service': 'config',
            'method': {
                'api': 'DescribePendingAggregationRequests',
                'boto3': 'describe_pending_aggregation_requests',
                'cli': 'describe-pending-aggregation-requests'
            },
            'options': reqParams
        });
        
        return true;
    }

    // config
    if (details.method == "GET" && details.url.match(/.+console\.aws\.amazon\.com\/config\/service\/iam\/listRoles\?/g)) {
        outputs.push({
            'region': region,
            'service': 'iam',
            'method': {
                'api': 'ListRoles',
                'boto3': 'list_roles',
                'cli': 'list-roles'
            },
            'options': reqParams
        });
        
        return true;
    }

    // config
    if (details.method == "GET" && details.url.match(/.+console\.aws\.amazon\.com\/config\/service\/listS3Buckets\?/g)) {
        outputs.push({
            'region': region,
            'service': 's3',
            'method': {
                'api': 'ListBuckets',
                'boto3': 'list_buckets',
                'cli': 'list-buckets'
            },
            'options': reqParams
        });
        
        return true;
    }

    // config
    if (details.method == "GET" && details.url.match(/.+console\.aws\.amazon\.com\/config\/service\/listSnsTopics\?/g)) {
        outputs.push({
            'region': region,
            'service': 'sns',
            'method': {
                'api': 'ListTopics',
                'boto3': 'list_topics',
                'cli': 'list-topics'
            },
            'options': reqParams
        });
        
        return true;
    }

    // xray
    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/xray\/data\/proxy\?call=GetEncryptionConfig&/g)) {
        outputs.push({
            'region': region,
            'service': 'xray',
            'method': {
                'api': 'GetEncryptionConfig',
                'boto3': 'get_encryption_config',
                'cli': 'get-encryption-config'
            },
            'options': reqParams
        });
        
        return true;
    }

    // xray
    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/xray\/data\/proxy\?call=GetSamplingRules&/g)) {
        outputs.push({
            'region': region,
            'service': 'xray',
            'method': {
                'api': 'GetSamplingRules',
                'boto3': 'get_sampling_rules',
                'cli': 'get-sampling-rules'
            },
            'options': reqParams
        });
        
        return true;
    }

    // xray
    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/xray\/data\/proxy\?call=GetSamplingStatisticSummaries&/g)) {
        outputs.push({
            'region': region,
            'service': 'xray',
            'method': {
                'api': 'GetSamplingStatisticSummaries',
                'boto3': 'get_sampling_statistic_summaries',
                'cli': 'get-sampling-statistic-summaries'
            },
            'options': reqParams
        });
        
        return true;
    }

    // opsworks
    if (details.method == "POST" && details.url.match(/.+console\.aws\.amazon\.com\/opsworks\/k\/DescribeServers\?/g)) {
        outputs.push({
            'region': region,
            'service': 'opsworkscm',
            'method': {
                'api': 'DescribeServers',
                'boto3': 'describe_servers',
                'cli': 'describe-servers'
            },
            'options': reqParams
        });
        
        return true;
    }

}
