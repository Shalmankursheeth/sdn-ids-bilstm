import paramiko
import json
import time

# Function to read the JSON file remotely from the VM
def read_eve_json_ssh(vm_ip, vm_username, vm_password, json_file_path):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=vm_ip, username=vm_username, password=vm_password)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh_client.exec_command(f"cat {json_file_path}")
    data = json.loads(ssh_stdout.read().decode('utf-8'))
    ssh_client.close()
    return data

# Function to check for alerts with severity level 1
def check_alerts(data):
    for event in data:
        if 'alert' in event and event['alert']['severity'] == '1':
            return event['src_ip']
    return None

# Function to isolate IP address
def isolate_ip(ip_address):
    # Add your code here to isolate the IP address
    print(f"Isolating IP address: {ip_address}")

# Main function
def main():
    vm_ip = '192.168.0.1'  # IP address of the VM where the eve.json file resides
    vm_username = 'shalman'  # SSH username for the VM
    vm_password = 'Shalman@123'  # SSH password for the VM
    json_file_path = '/var/log/suricata/eve.json'  # Path to the Suricata eve.json file on the VM

    # Replace this loop with a more efficient method of monitoring the JSON file for changes
    while True:
        try:
            data = read_eve_json_ssh(vm_ip, vm_username, vm_password, json_file_path)
            ip_address = check_alerts(data)
            if ip_address:
                print(f"Alert detected with severity level 1. Isolating IP: {ip_address}")
                isolate_ip(ip_address)
            else:
                print("No alert with severity level 1 detected.")
        except Exception as e:
            print(f"Error occurred: {e}")
        
        # Sleep for a certain period before checking again
        time.sleep(60)  # Adjust the time interval as needed

if __name__ == "__main__":
    main()
