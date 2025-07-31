# Splunk ES Bulk Detection Creator (API Automation)

This project automates the creation of Event-Based Detections (Findings) in Splunk Enterprise Security (ES) using the Splunk REST API (port 8089) and Python.

It supports:

-   Bulk detection creation from a YAML file (**detections.yml**)
    
-   Looping through multiple Splunk ES servers (**servers.csv**)
    
-   Shared credentials stored in a secure config file (**creds.ym**)
    
-   Event-Based Detection (EBD) creation with risk, notable, entities, and adaptive response actions
    

----------

### Features:

-   Automated detection creation using the Splunk API (port 8089).
    
-   Bulk-create detections across multiple servers.
    
-   Full control of detection fields (search, severity, risk, domain, entities, actions).
    
-   Supports YAML for flexible nested configuration (entities, risks, annotations).
    
-   Ideal for multi-environment deployments (Dev, QA, Prod).
    

----------

### Project Structure:

-   **create_detections.py**: Main Python script to push detections
    
-   **creds.yml**: Shared Splunk credentials (username/password)
    
-   **servers.csv**: List of Splunk ES servers
    
-   **detections.yml**: Detection definitions
    

    

----------

### Prerequisites:

-   Python 3.9 or higher
    
-   Splunk Enterprise Security 8.x or higher
    
-   Splunk REST API enabled (port 8089)
    
-   Access credentials with ES Content Management permissions
    

----------

### Installation:

1.  Clone this repository or copy the files.
    
2.  Install dependencies using:  
    pip install requests pyyaml
    
3.  Ensure you have API access to your Splunk ES instances over port 8089.
    

----------

### Configuration:

#### 1.  Credentials (creds.yml):  
    This file stores the shared Splunk credentials for all servers.  
    Example:  
    ```
    username: "admin"  
    password: "changeme"
    
#### 2.  Servers (servers.csv):  
    List all Splunk ES servers (one per line).  
    Example:  
    ```
    host  
    192.168.128.33  
    192.168.128.34  
    192.168.128.35
    
    
####  3.  Detections (detections.yml):  

   Define detections with SPL, scheduling, risk, severity, and ES fields.  
    Example:  
    
   ```
detections:
  - name: "Threat - api_detection_created_1 - Rule"
    title: "API Detection Created 1"
    description: "First API-created detection to monitor failed login attempts."
    search: "index=auth sourcetype=linux_secure action=failure | stats count by user"
    cron: "*/10 * * * *"
    earliest: "-15m"
    latest: "now"
    severity: "high"
    domain: "access"
    investigation_type: "intermediate_finding"
    risk_message: "Repeated failed login attempts detected"
    entities:
      - risk_object_field: "user"
        risk_object_type: "user"
        risk_score: 5
    risks:
      - risk_object_field: "user"
        risk_object_type: "user"
        risk_score: 5
    actions: "notable, risk"

  - name: "Threat - api_detection_created_2 - Rule"
    title: "API Detection Created 2"
    description: "Second API-created detection to monitor high CPU usage on endpoints."
    search: "index=os sourcetype=perfmon_cpu | stats avg(cpu) by host | where avg(cpu) > 90"
    cron: "*/5 * * * *"
    earliest: "-10m"
    latest: "now"
    severity: "medium"
    domain: "endpoint"
    investigation_type: "default"
    risk_message: "Endpoint CPU usage over threshold"
    entities:
      - risk_object_field: "host"
        risk_object_type: "system"
        risk_score: 4
    risks:
      - risk_object_field: "host"
        risk_object_type: "system"
        risk_score: 4
    actions: "notable, risk"

  - name: "Threat - api_detection_created_3 - Rule"
    title: "API Detection Created 3"
    description: "Third API-created detection for anomalous outbound traffic volume."
    search: "index=network sourcetype=netflow | stats sum(bytes) as total_bytes by dest_ip | where total_bytes > 100000000"
    cron: "*/15 * * * *"
    earliest: "-30m"
    latest: "now"
    severity: "critical"
    domain: "network"
    investigation_type: "intermediate_finding"
    risk_message: "Potential data exfiltration detected"
    entities:
      - risk_object_field: "dest_ip"
        risk_object_type: "system"
        risk_score: 8
    risks:
      - risk_object_field: "dest_ip"
        risk_object_type: "system"
        risk_score: 8
    actions: "notable, risk"
```
----------

### Usage:  
Run the script to push detections to all servers listed in servers.csv:  
python create_detections.py

----------

#### Verification:  
After running the script:

1.  Log in to Splunk ES.
    
2.  Go to Content Management and search for your detection (for example: api_detection_created).
    
3.  Confirm that detections are visible and enabled.
    

----------

#### Security Notes:

-   Store creds.yml securely and do not commit credentials to version control.
    
-   Use a dedicated Splunk service account with the minimal ES permissions needed for detection creation.
    

----------

#### Next Steps:

-   Add MITRE ATT&CK mappings (tactic and technique IDs) to detections.
    
-   Export existing ES detections to YAML for cloning.
    
-   Implement retry logic for server outages.
    

----------

#### Example Command:  
python create_detections.py

Example Output:  
```
=== Processing server: {host_address} ===  
[*] [192.168.128.33] Creating detection: Threat - api_detection_created_1 - Rule  
[+] [192.168.128.33] Detection created and updated: Threat - api_detection_created_1 - Rule  
[✅] Bulk YAML detection creation complete across all servers!
```
