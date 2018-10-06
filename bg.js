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
    analyseRequest,
    {urls: ["<all_urls>"]},
    ["requestBody","blocking"]
);

fetch("combined.json")
  .then(response => response.json())
  .then(json => combined = json);

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

function analyseRequest(details) {
    var requestBody = null;
    var jsonRequestBody = null;

    if (details.type != "xmlhttprequest") return;

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
            
            requests_with_potentials.push({
                'url': details.url,
                'potentials': potentials,
                'service': service,
                'requestBody': requestBody
            });
            console.warn("---");
        }
    }
}
