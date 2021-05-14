import ballerina/io;
import ballerina/log;
import ballerina/file;

map<json> cves = {};
string[][] cve_desc = [];

string bufferErrorCWE = "CWE-119";
string[] bufferErrorCWEs = ["CWE-119","CWE-120","CWE-125","CWE-466","CWE-680","CWE-786","CWE-787","CWE-788","CWE-805","CWE-822","CWE-823","CWE-824"];
string[] bufferErrorAllCWEs = ["CWE-119","CWE-120","CWE-125","CWE-466","CWE-680","CWE-786","CWE-787","CWE-788","CWE-805","CWE-822","CWE-823","CWE-824",
                            "CWE-20","CWE-128","CWE-129","CWE-131","CWE-190","CWE-193","CWE-195","CWE-839","CWE-843","CWE-1257","CWE-1260"];


function closeRc(io:ReadableCharacterChannel rc) {
    var result = rc.close();
    if (result is error) {
        log:printError("Error occurred while closing character stream", err = result);
    }
}

function closeWc(io:WritableCharacterChannel wc) {
    var result = wc.close();
    if (result is error) {
        log:printError("Error occurred while closing character stream", err = result);
    }
}

function writeToFile() returns error? {
    var writeCsvResult = writeToCSV();
    var writeJsonResult = writeToJson();
}

function writeToJson() returns error? {
    string path = "./files/write/data.json";
    io:WritableByteChannel wbc = check io:openWritableFile(path);

    io:WritableCharacterChannel wch = new (wbc, "UTF8");
    io:println("Number of CVEs :" + cves.length().toString());
    cves.forEach(function(json cve) {
        error? result = wch.writeJson(cve);
    });
    closeWc(wch);
}

function writeToCSV() returns error? {
    string path = "./files/write/data.csv";
    check io:fileWriteCsv(path, cve_desc);
}

function read(string path) returns @tainted json|error {

    io:ReadableByteChannel rbc = check io:openReadableFile(path);

    io:ReadableCharacterChannel rch = new (rbc, "UTF8");
    var result = rch.readJson();
    closeRc(rch);
    return result;
}

function isOfBufferErrorCWE(json cve) returns boolean {
    json|error problemtype_data = cve.problemtype.problemtype_data;
    if (problemtype_data is error) {
        log:printError("Error occurred while reading json: ", err = problemtype_data);
    } else {
        json[] problemtype_data_arr = <json[]>problemtype_data;
        foreach var problemtype_data_item in problemtype_data_arr {
            json|error description = problemtype_data_item.description;
            if (description is error) {
                log:printError("Error occurred while reading json: ", err = description);
            } else {
                json[] desc_arr = <json[]>description;
                foreach var desc_item in desc_arr {
                    json|error value = desc_item.value;
                    if (value is error) {
                        log:printError("Error occurred while reading json: ", err = value);
                    } else {
                        // if (bufferErrorCWE.includes(value.toString())) {
                        //     return true;
                        // }
                        foreach var bufferErrorCWE in bufferErrorCWEs {
                            if (bufferErrorCWE.includes(value.toString())) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    return false;
} 

function processCVEData(json rResult) {  
    map<json> res = <map<json>> rResult;
    json[] cve_items = <json[]>res["CVE_Items"];

    int count = 0;

    cve_items.forEach(function(json data) {
        json|error cve = data.cve;
        if (cve is error) {
            log:printError("Error occurred while reading json: ", err = cve);
        } else {
            if (cve.toString().includes("android")) {
                json|error description_data = cve.description.description_data;
                if (description_data is error) {
                    log:printError("Error occurred while reading json: ", err = description_data);
                } else {
                    json[] desc_arr = <json[]>description_data;

                    // string desc = desc_arr.toString().toLowerAscii();
                    // if (isOfBufferErrorCWE(cve)) {
                    //     count += 1;
                    //     json cve_id = checkpanic cve.CVE_data_meta.ID;
                    //     string cveUrl = "https://nvd.nist.gov/vuln/detail/" + cve_id.toString();
                    //     // io:println(cveUrl);
                    //     map<json> convert = <map<json>> data;
                    //     convert["CVE_URL"] = cveUrl;
                    //     cves[cve_id.toString()] = convert;
                    //     cve_desc[cve_desc.length()] = [cveUrl, desc];
                    // }

                    foreach var item in desc_arr {
                        json|error value = item.value;
                        if (value is error) {
                            log:printError("Error occurred while reading json: ", err = value);
                        } else {
                            string desc = value.toString().toLowerAscii();
                            if (isOfBufferErrorCWE(cve)) {
                                count += 1;
                                json cve_id = checkpanic cve.CVE_data_meta.ID;
                                string cveUrl = "https://nvd.nist.gov/vuln/detail/" + cve_id.toString();
                                // io:println(cveUrl);
                                map<json> convert = <map<json>> data;
                                convert["CVE_URL"] = cveUrl;
                                cves[cve_id.toString()] = convert;
                                cve_desc[cve_desc.length()] = [cveUrl, desc];
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
    // io:println("Andriod + Buffer CVEs :" + count.toString());              
}

function processResults(file:MetaData[] readDirResults) {
    foreach var item in readDirResults {
        string filePath = item.absPath;
        // io:println("Preparing to read the content");

        var rResult = read(filePath);
        if (rResult is error) {
            log:printError("Error occurred while reading json: ", err = rResult);
        } else {
            processCVEData(rResult);
        }   
    }
}

public function main() {
    file:MetaData[]|error readDirResults = file:readDir("./files/read/");

    if (readDirResults is error) {
        log:printError("Cannot read nvd json data directory: ", err = readDirResults); 
    } else {
        processResults(readDirResults);
    }

    error? result = writeToFile();
    if (result is error) {
        log:printError("Cannot write nvd json data: ", err = result); 
    }
}
