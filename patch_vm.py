import argparse
import json
import sys
import logging

logging.basicConfig(format='[%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S%p]')

ignore_keywords = ["Package", "Installed", "Version", "Required", "Vulnerable", "Detected"]

packages = []

def is_valid_package_report(line):
    for keyword in ignore_keywords:
        if keyword in line:
            return False
    return True

def list_package_to_update(detections, severity):
    for detection in detections:
        try:
            if int(detection['SEVERITY']) >= severity:
                results = detection['RESULTS'].split('\n')
		
                for result in results:
                    if is_valid_package_report(result):
                        res = result.split('\t')
                        if len(res) == 3:
                            package = {
                                "package_name": str(res[0]),
                                "installed_version": str(res[1]),
                                "required_version": str(res[2]),
                            }                        
                            packages.append(package)

        except Exception as e:
            logging.error(e)
            sys.exit(1)

def patch_vm(qualys_json_file, severity):
    try:
        with open(qualys_json_file, 'r') as f:
            data = json.load(f)['HOST_LIST_VM_DETECTION_OUTPUT']['RESPONSE']['HOST_LIST']['HOST']
    
        if type(data) == list:
            for row in data:
                detections = row['DETECTION_LIST']['DETECTION']
                list_package_to_update(detections, severity)
    
        elif type(data) == dict:
            list_package_to_update(data['DETECTION_LIST']['DETECTION'], severity)

    except Exception as e:
        logging.error(e)
        sys.exit(1)

    print("=============================")
    print(" List of vulnerable packages ")
    print("=============================")
    for package in packages:
        print(package)
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
                "-f", 
                "--qualys_json_file", 
                metavar="qualys_json_file",
                type=str,
                help="the qualys vulnerability json file"
    )

    parser.add_argument(
                "-s",
                "--severity",
                metavar="severity",
                type=int,
                help="the severity level of the vulnerability"
    )
    
    args = parser.parse_args()
    
    qualys_json_file = args.qualys_json_file
    severity = args.severity
    
    if not qualys_json_file or not severity:
        print("Usage: ./patch_vm.py -f <QUALYS_JSON_FILE> -s <SEVERITY>")
        sys.exit(1)

    patch_vm(qualys_json_file, severity)
