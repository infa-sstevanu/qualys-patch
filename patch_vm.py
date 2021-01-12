import argparse
import json
import logging
import subprocess
import sys

logging.basicConfig(format='[%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S%p]')

ignore_keywords = ["Package", "Installed", "Version", "Required", "Vulnerable", "Detected"]

packages = []

def update_packages(option):
    def execute_yum_install(cmd):
        print(cmd)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        print(output.decode("utf-8"))

    for package in packages:
        package_name = package['package_name']
        required_version = package['required_version']
        try:
            cmd = "yum install {}-{} -y".format(package_name, required_version)
            execute_yum_install(cmd)

        except Exception as e:
            logging.error(e)
            cmd = "yum install --skip-broken {}-{} -y".format(package_name, required_version)
            execute_yum_install(cmd)

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

def patch_vm(qualys_json_file):
    # Severity level
    severity = 3

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
    print("")

    if not len(packages):
        print("No vulnerable packages with severity level {}".format(severity))
        sys.exit(0)

    for package in packages:
        package_name = package['package_name']
        installed_version = package['installed_version']
        required_version = package['required_version']

        print("PackageName: {}, InstalledVersion: {}, RequiredVersion: {}".format(package_name, installed_version, required_version))

    while True:
        print("[1] Update all packages")
        print("[0] Exit the script")

        user_input = input("Enter your option: ")
        if user_input == '0':
            sys.exit(0)
        if user_input == '1':
            update_packages(1)
            break
         
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument(
                "-f", 
                "--qualys_json_file", 
                metavar="qualys_json_file",
                type=str,
                help="the qualys vulnerability json file"
    )
    
    args = parser.parse_args()

    qualys_json_file = args.qualys_json_file
    
    if not qualys_json_file:
        print("Usage: ./patch_vm.py -f <QUALYS_JSON_FILE>")
        sys.exit(1)

    patch_vm(qualys_json_file)
