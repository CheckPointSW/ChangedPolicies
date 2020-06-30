# ChangedPolicies
Check Point ChangedPolicies tool allows the user to know which policies were affected by changes that were made in the last published session.
This is useful to determine which policies should be installed.

You can adjust the code according to your organization’s policy / needs.

  - This tool can be executed on Management Server / Multi-Domain servers of version of R80.10 and up.

## Instructions
Clone the repository with this command:
```git
git clone https://github.com/CheckPointSW/ChangedPolicies
``` 
or by clicking the _‘Download ZIP’_ button. 

Download and install the [Check Point API Python SDK](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk) 
repository, follow the instructions in the SDK repository.

## Usage Syntax
```python ChangedPolicies.py [-c changes] [-u username] [-p password] [-m management] [-d domain] [-o output-file] [--port port]```

• [-c --changes] (Optional): The \'show-changes\' API command output encoded in base 64. 
Use this flag for integration with Smart Task.
For more details follow the instructions below in the ["Integration with Smart Task"](#Integration with Smart Task) section

• [-d --domain] (Optional): The name or uid of the Security Management Server domain.  
When running the command on a Multi domain server the default domain is the "MDS".

• [-o --output-file] (Optional): The output file name. The location in which to save the resulting .Json file.   
The default is the current directory with the name 'Changed_policies.json'. 
 
• [--port] (Optional): The port of WebAPI server on Security Management Server.  
Default value is 443.

Use "-h" option in order to see the full list of options to configure the tool  

## Examples
*   Running the tool on a remote management server: 
<br>```python ChangedPolicies.py  -m 172.23.78.160 -u James -p MySecretPassword!```
<br>The tool runs on a remote management server with IP address 172.23.78.160.

*   Running the tool on a Multi-Domain Server for a specific domain: 
<br>```python ChangedPolicies.py  -d 172.23.78.152 -u James -p MySecretPassword!```

*   Running the tool on a Security Management Server with specific output file name: 
<br>```python ChangedPolicies.py  -o "json_file.json" -u James -p MySecretPassword!```


## Output
The tool generates a Json file with the changed policies for the last published session. 
if you execute this tool multiple times it will update the file with the aggregated changes.
 
Example of output:
```Git

{
    "Global": {
        "4631ed09-6663-4d0c-95e0-95e26ef2a927": [
            "Standard"
        ]
    },
    "my_domain": {
        "02d744e0-eb92-40d6-bb59-186c522b35c1": [
            "policy package 1",
            "Standard"
        ]
    }
}

``` 

## Integration with Smart Task
This tool can be integrated with Smart Task which is supported from R80.40.

### Instructions:
* Install the Check Point API Python SDK, follow the instructions for
 [SDK usage from a management machine](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk#sdk-usage-from-a-management-machine).
* Copy the script 'ChangedPolicies.py' to your Management machine.
* Execute the command `api fingerprint -f json | jq -r '.[0] | .["fingerprint-sha1"]'` and save the output.
* Create file named `fingerprints.txt` in `/var/tmp/`. The content should be a Json that the key is the machine IP 
and the value is the fingerprint (the output of the command above).<br>
For example: <br>
     ```Git
    {
        "172.23.78.160": "6713548716C586ECDBF1A6693CB440071F1C89E6"
    } 
    ``` 
* Create new script in Smart Console <i>'GATEWAYS & SERVERS' > 'Scripts' > 'Script Repository' > 'new' </i> 
and call it 'Changed policies'. <br>
The content should contain the export command as in the SDK instruction above and the execution of the script 
using the '-c' / '--changes' flag with '$1' as value.<br>
For example: 
    ```Git
    
    export PYTHONPATH=$PYTHONPATH:/home/admin/cp_mgmt_api_python_sdk/
    
    python /var/tmp/ChangedPolicies.py -r true -c $1
    
    
    ``` 
* Create new Smart Task in Smart Console:
<br>&emsp;- Go to <i>'MANAGE & SETTINGS' > 'Tasks' > 'new'</i> and call it 'Changed policies'.
<br>&emsp;- Turn the task on.
<br>&emsp;- Under 'Trigger and Action' choose 'After Publish' as trigger and 'Run Script' as the action 
and select the script 'Changed policies' from the repository.
<br>&emsp;- Under 'Advanced' set the 'Time out' to be 300.
* Publish the changes.

For more information about Smart Task go to [R80.40 Administration Guide](https://sc1.checkpoint.com/documents/R80.40/WebAdminGuides/EN/CP_R80.40_SecurityManagement_AdminGuide/Content/Topics-SECMG/SmartTasks.htm?Highlight=smarttask)... #TODO:  add link

## limitations

* The script support only the changes of last published session.
* The tool doesn't support changes in Threat and HTTPS layers.
* The tool doesn't support shared layers.
* In case of changes in Global domain in Multi Domain machine, 
the script should be executed from the Global domain (use the flag `--domain Global`).  


## Development Environment
The tool is developed using Python language version 2.7, version 3.7 and [Check Point API Python SDK](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk).




