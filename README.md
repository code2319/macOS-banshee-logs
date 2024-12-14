# Tracing the BANSHEE Infostealer: Analysis of macOS Logs  
The purpose of this analysis is to understand and see what logs the infostealer generates.

## Lab Setup info
1. UTM 4.6.2 (104)
2. macOS Sonoma 14.7.1
3. Splunk Universal Forwarder
4. [CIS Apple macOS 14.0 Sonoma benchmark](files/CIS_Apple_macOS_14.0_Sonoma_Benchmark_v2.0.0.pdf) logging configuration

# Setup a Splunk Universal Forwarder
To forward data to Splunk Cloud Platform instance, perform the following procedures:

1. Download and install the universal forwarder software.
2. Download the Splunk universal forwarder credentials package (Apps -> Universal Forwarder) and copy it to the `/tmp` folder.
3. Install the Splunk universal forwarder credentials package on the universal forwarder machine. See [Install and configure the Splunk Cloud Platform universal forwarder credentials package](http://docs.splunk.com/Documentation/Forwarder/9.3.2/Forwarder/ConfigSCUFCredentials).
4. Install universal forwarder credentials package (`splunkclouduf.spl`) by entering the following command: `$SPLUNK_HOME/bin/splunk install app /tmp/splunkclouduf.spl`.<br>
5. When you are prompted for a user name and password, enter the user name and password for the Universal Forwarder. The following message displays if the installation is successful: `App '/tmp/splunkclouduf.spl' installed`.
6. Configure inputs to collect data from the host that the universal forwarder is on. For an overview, see [Configure the universal forwarder](http://docs.splunk.com/Documentation/Forwarder/9.3.2/Forwarder/Configuretheuniversalforwarder).
I have set up the following folders (lots of spam, period I don't recommend):
```
1. /var/log
2. /Library/Logs
3. ~/Library/Logs
4. /private/var/db/diagnostics
```

Splunk universal forwarder logs:
```
/Applications/SplunkForwarder/var/log/splunk/splunkd.log
```
Configuration files:
```
/Applications/SplunkForwarder/etc/system/local
```
Debug command:
```
/Applications/SplunkForwarder/bin/splunk btool outputs list --debug
```

# CIS: Logging and Auditing
Applied the following recommendations from the logging and auditing section:
1. Enabled security auditing (auditd)
2. Changed security auditing flags to `-all`
3. Security auditing retention (`expire-after`) setup to `5G`
4. Firewall logging is enabled
plus


# Analysing stealer logs
Since the source code has been leaked we can play around with it: write our own [python-server](files/server.py), change the C2 server to ours, disable the `checkVM()` function, and disable `system("killall Terminal");` to see what logs it generates. Luckily for us, *at least in build* `T0JVJJy6tgNdmygyRfN0eRaIiZq2uw` terminal logs come out of box `#define DebugLog(...) NSLog(__VA_ARGS__)`, meaning if `DebugLog()` is defined, we can see that log in the terminal.
<details>
<summary>banshee debug log</summary>

```
% ./banshee run_controller 123
2024-12-12 21:45:11.347 banshee[1619:30946] Password saved successfully.
2024-12-12 21:45:11.758 banshee[1619:30946] Delimiter not found or index out of bounds
2024-12-12 21:45:11.758 banshee[1619:30946] Delimiter not found or index out of bounds
2024-12-12 21:45:11.758 banshee[1619:30946] Delimiter not found or index out of bounds
2024-12-12 21:45:11.758 banshee[1619:30946] Delimiter not found or index out of bounds
2024-12-12 21:45:11.758 banshee[1619:30946] Starting to fetch IP...
2024-12-12 21:45:11.768 banshee[1619:30946] Starting AppleScript execution.
2024-12-12 21:45:11.768 banshee[1619:30946] Attempt 1 to execute AppleScript.
2024-12-12 21:45:11.907 banshee[1619:30946] Received response from IP API.
2024-12-12 21:45:11.907 banshee[1619:30946] IP data parsed successfully: {
    cityName = Belgrade;
    continent = Europe;
    continentCode = EU;
    countryCode = RS;
    countryName = Serbia;
    currency =     {
        code = RSD;
        name = "Serbian Dinar";
    };
    ipAddress = "";
    ipVersion = 4;
    isProxy = 0;
    language = Serbian;
    latitude = "";
    longitude = "";
    regionName = Beograd;
    timeZone = "+02:00";
    timeZones =     (
        "Europe/Belgrade"
    );
    tlds =     (
        ".rs",
        ".\U0441\U0440\U0431"
    );
    zipCode = ;
}
2024-12-12 21:45:12.098 banshee[1619:30946] All good
2024-12-12 21:45:12.098 banshee[1619:30946] {
    "Activation Lock Status" = Disabled;
    "BUILD_ID" = T0JVJJy6tgNdmygyRfN0eRaIiZq2uw;
    "Boot Mode" = Normal;
    "Boot Volume" = "Macintosh HD";
    Chip = "Apple M3 Pro (Virtual)";
    "Computer Name" = "user\U2019s Virtual Machine";
    "Hardware UUID" = "D538657A-8AD3-517E-ACC6-913A9FD37985";
    "Kernel Version" = "Darwin 23.6.0";
    Memory = "4 GB";
    "Model Identifier" = "VirtualMac2,1";
    "Model Name" = "Apple Virtual Machine 1";
    "Model Number" = "VM0001ZE/A";
    "OS Loader Version" = "10151.140.19.700.2";
    "Provisioning UDID" = "0000FE00-92F510A9A0C424BA";
    "Secure Virtual Memory" = Enabled;
    "Serial Number (system)" = ZFVC16YYR4;
    "System Firmware Version" = "10151.140.19.700.2";
    "System Integrity Protection" = Enabled;
    "System Version" = "macOS 14.7.1 (23H222)";
    "Time since boot" = "30 minutes, 7 seconds";
    "Total Number of Cores" = 5;
    "User Name" = "user (user)";
    "ip_info" =     {
        cityName = Belgrade;
        continent = Europe;
        continentCode = EU;
        countryCode = RS;
        countryName = Serbia;
        currency =         {
            code = RSD;
            name = "Serbian Dinar";
        };
        ipAddress = "";
        ipVersion = 4;
        isProxy = 0;
        language = Serbian;
        latitude = "";
        longitude = "";
        regionName = Beograd;
        timeZone = "+02:00";
        timeZones =         (
            "Europe/Belgrade"
        );
        tlds =         (
            ".rs",
            ".\U0441\U0440\U0431"
        );
        zipCode = ;
    };
    "system_os" = macos;
    "system_password" = "";
}
2024-12-12 21:45:12.099 banshee[1619:30946] System info written to file successfully.
2024-12-12 21:45:20.411 banshee[1619:30946] AppleScript output: 
2024-12-12 21:45:20.412 banshee[1619:30946] AppleScript executed successfully on attempt 1.
2024-12-12 21:45:20.412 banshee[1619:30946] Running command: mv /Users/user/tempFolder-32555443 /var/folders/tr/025lt0413vq2kl72y877f4n80000gn/T/WU5v2kgvf5ksgHOyauCwPQzN4/FileGrabber
2024-12-12 21:45:20.424 banshee[1619:30946] AppleScript executed and files moved successfully.
2024-12-12 21:45:20.425 banshee[1619:30946] Source directory /Users/user/Library/Application Support/Exodus/exodus.wallet is empty or does not exist, skipping.
2024-12-12 21:45:20.425 banshee[1619:30946] Source directory /Users/user/Library/Application Support/electrum/wallets is empty or does not exist, skipping.
2024-12-12 21:45:20.425 banshee[1619:30946] Source directory /Users/user/Library/Application Support/Coinomi/wallets is empty or does not exist, skipping.
2024-12-12 21:45:20.425 banshee[1619:30946] Source directory /Users/user/Library/Application Support/Guarda/Local Storage/leveldb is empty or does not exist, skipping.
2024-12-12 21:45:20.425 banshee[1619:30946] Source directory /Users/user/Library/Application Support/walletwasabi/client/Wallets is empty or does not exist, skipping.
2024-12-12 21:45:20.425 banshee[1619:30946] Source directory /Users/user/Library/Application Support/atomic/Local Storage/leveldb is empty or does not exist, skipping.
2024-12-12 21:45:20.425 banshee[1619:30946] Source directory /Users/user/Library/Application Support/Ledger Live is empty or does not exist, skipping.
2024-12-12 21:45:20.460 banshee[1619:31298] Data posted successfully
2024-12-12 21:45:20.462 banshee[1619:30946] Path does not exist: /Users/user/tempFolder-32555443
```
</details><br>

But these were terminal logs, what about auditd logs? Since we know the time the stealer was run, we can see the logs using the following command:
```
% log show --start "2024-12-12 21:45:11" --end "2024-12-12 21:45:21" --info --debug > banshee.log
```

## Unified Logging
### System info collection (system_profiler)
```
% log show --predicate 'process="system_profiler"' --start "2024-12-12 21:45:11" --end "2024-12-12 21:45:21" --info --debug
Filtering the log data using "process == "system_profiler""
2024-12-12 21:45:11.359548+0100 0x7949     Info        0x0                  1622   0    system_profiler: (SPSupport) [com.apple.SPSupport:Reporting] -[SPDocument reportForDataType:] -- Dispatching helperTool request for dataType SPSoftwareDataType.
2024-12-12 21:45:11.359782+0100 0x794a     Info        0x0                  1622   0    system_profiler: (SPSupport) [com.apple.SPSupport:Reporting] -[SPDocument _reportFromHelperToolForDataType:completionHandler:]_block_invoke -- Launching task to collect SPSoftwareDataType
2024-12-12 21:45:11.364968+0100 0x794d     Info        0x0                  1623   0    system_profiler: (SPSupport) [com.apple.SPSupport:Reporting] -[SPDocument _reportFromBundlesForDataType:completionHandler:] -- Called on the main thread for dataType SPSoftwareDataType. Re-dispatching to global_queue.
2024-12-12 21:45:11.365089+0100 0x794e     Info        0x0                  1623   0    system_profiler: (SPSupport) [com.apple.SPSupport:Reporting] -[SPDocument _reportFromBundlesForDataType:] -- Starting task to collect SPSoftwareDataType
...
2024-12-12 21:45:11.614578+0100 0x7949     Info        0x0                  1622   0    system_profiler: (SPSupport) [com.apple.SPSupport:Reporting] -[SPDocument reportForDataType:] -- Dispatching helperTool request for dataType SPHardwareDataType.
2024-12-12 21:45:11.614695+0100 0x794a     Info        0x0                  1622   0    system_profiler: (SPSupport) [com.apple.SPSupport:Reporting] -[SPDocument _reportFromHelperToolForDataType:completionHandler:]_block_invoke -- Launching task to collect SPHardwareDataType
2024-12-12 21:45:11.621749+0100 0x7953     Info        0x0                  1625   0    system_profiler: (SPSupport) [com.apple.SPSupport:Reporting] -[SPDocument _reportFromBundlesForDataType:completionHandler:] -- Called on the main thread for dataType SPHardwareDataType. Re-dispatching to global_queue.
2024-12-12 21:45:11.621833+0100 0x7954     Info        0x0                  1625   0    system_profiler: (SPSupport) [com.apple.SPSupport:Reporting] -[SPDocument _reportFromBundlesForDataType:] -- Starting task to collect SPHardwareDataType
```

### dscl
Let's try to find logs related to checking the entered password using the `dscl` command. Since the source code used `NSTask` in the `exec` function, it spawned a child process, so searching the original process will not yield any results:
```
% log show --predicate 'composedMessage contains "dscl" OR process contains "dscl"' --start "2024-12-12 21:45:11" --end "2024-12-12 21:45:21" --info --debug
Filtering the log data using "process CONTAINS "dscl" OR composedMessage CONTAINS "dscl""
Timestamp                       Thread     Type        Activity             PID    TTL  
2024-12-12 21:45:11.238323+0100 0x7942     Activity    0x13a70              1621   0    dscl: (CFOpenDirectory) Open a given node
2024-12-12 21:45:11.240016+0100 0x7942     Default     0x13a70              1621   0    dscl: (libxpc.dylib) [com.apple.xpc:connection] [0x600001044000] activating connection: mach=true listener=false peer=false name=com.apple.system.opendirectoryd.api
2024-12-12 21:45:11.240690+0100 0x76d4     Info        0x13a70              119    0    opendirectoryd: [com.apple.opendirectoryd:session] UID: 501, EUID: 501, GID: 20, EGID: 20, PID: 1621, PROC: dscl ODNodeCreateWithNameAndOptions request, SessionID: 00000000-0000-0000-0000-000000000000, Name: <private>, Options: 0x0
2024-12-12 21:45:11.242897+0100 0x7942     Activity    0x13a71              1621   0    dscl: (CFOpenDirectory) Retrieve record from node
2024-12-12 21:45:11.242901+0100 0x7942     Activity    0x13a72              1621   0    dscl: (CFOpenDirectory) Querying records from directories
2024-12-12 21:45:11.243128+0100 0x78e3     Info        0x13a72              119    0    opendirectoryd: [com.apple.opendirectoryd:session] UID: 501, EUID: 501, GID: 20, EGID: 20, PID: 1621, PROC: dscl ODQueryCreateWithNode request, NodeID: DFD1BF07-4D91-4198-9ACF-B0F3707E22F2, RecordType(s): dsRecTypeStandard:Users, Attribute: dsAttrTypeStandard:RecordName, MatchType: EqualTo, Equality: CaseIgnore, Value(s): <private>, Requested Attributes: <none>, Max Results: 1
2024-12-12 21:45:11.247745+0100 0x7942     Activity    0x13a73              1621   0    dscl: (CFOpenDirectory) Verify basic credentials
2024-12-12 21:45:11.247839+0100 0x76d4     Info        0x13a73              119    0    opendirectoryd: [com.apple.opendirectoryd:session] UID: 501, EUID: 501, GID: 20, EGID: 20, PID: 1621, PROC: dscl ODRecordVerifyPassword request, NodeID: DFD1BF07-4D91-4198-9ACF-B0F3707E22F2, RecordType: dsRecTypeStandard:Users, Record: <private>
2024-12-12 21:45:11.346074+0100 0x7942     Activity    0x13a74              1621   0    dscl: (CFOpenDirectory) Closing a node reference
2024-12-12 21:45:11.346143+0100 0x76d4     Info        0x13a74              119    0    opendirectoryd: [com.apple.opendirectoryd:session] UID: 501, EUID: 501, GID: 20, EGID: 20, PID: 1621, PROC: dscl ODNodeRelease request, NodeID: DFD1BF07-4D91-4198-9ACF-B0F3707E22F2
2024-12-12 21:45:11.346638+0100 0x78e4     Info        0x0                  119    0    opendirectoryd: [com.apple.opendirectoryd:session] PID: 1621, Client: 'dscl', exited with 0 session(s), 0 node(s) and 0 active request(s)
--------------------------------------------------------------------------------------------------------------------
Log      - Default:          1, Info:                5, Debug:             0, Error:          0, Fault:          0
Activity - Create:           5, Transition:          0, Actions:           0
```

### C2
To find the data transfer on C2 we can use the following command:
```
% log show --predicate 'subsystem="com.apple.network"' --start "2024-12-12 21:45:11" --end "2024-12-12 21:45:21" --info --debug
```
The full log can be found [here](files/com.apple.network.log), here is the fact of the transfer:
```
2024-12-12 21:45:20.459870+0100 0x7a42     Default     0x0                  1619   0    banshee: (Network) [com.apple.network:connection] [C4 37BD558C-A5D9-4ED2-8CF3-A38F63F7986E 127.0.0.1:8000 tcp, url hash: 5fe282c6, definite, attribution: developer] cancelled
	[C4 D935AE40-57F8-4924-9BCC-AA9E2B8CE0B6 127.0.0.1:49281<->127.0.0.1:8000]
	Connected Path: satisfied (Path is satisfied), viable, interface: lo0
	Privacy Stance: Not Eligible
	Duration: 0.012s, TCP @0.000s took 0.001s
	bytes in/out: 111/85518, packets in/out: 3/7, rtt: 0.001s, retransmitted bytes: 0, out-of-order bytes: 0
	ecn packets sent/acked/marked/lost: 0/0/0/0
```

#### C2 request
Now let's see what came to our C2
```
% python3 server.py
Starting HTTP server on port 8000...
Received POST request to /send/
Headers: Host: 127.0.0.1:8000
Content-Type: application/json
Connection: keep-alive
Accept: */*
User-Agent: banshee (unknown version) CFNetwork/1498.700.2 Darwin/23.6.0
Content-Length: 83298
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate


Body: {"data":"base64encodedAndEncryptedData:i22rA7cWN57YefE:HofPYbB9JeABDQGeL1U4oUwws"}
```
Where
```
HofPYbB9JeABDQGeL1U4oUwws - is the original filename extracted from our system (without the .zip extension);
i22rA7cWN57YefE - is the key we can use to decrypt our data;
base64encodedData - is the base64 encoded and encrypted data.
```
To decrypt intercepted data, we can use [this](files/decryptor.py) python-script:
```
% decryptor.py server-files/HofPYbB9JeABDQGeL1U4oUwws.json
```

# Splunk Logs
We can check which source generates more logs `index=* | stats count by source | sort -count`
<details>
<summary>sources stats</summary>

```
/var/log/com.apple.xpc.launchd/launchd.log	62396
/var/log/install.log	1138
/Library/Logs/DiagnosticReports/shutdown_stall_2024-12-13-003247_users-Virtual-Machine.shutdownStall	595
/var/log/asl/Logs/aslmanager.20241212T204313+01	266
/var/log/asl/Logs/aslmanager.20241213T000519+01	263
/var/log/asl/Logs/aslmanager.20241213T003227+01	260
/private/var/db/diagnostics/logdata.statistics.0.txt	121
/var/log/system.log	87
/private/var/db/diagnostics/logdata.statistics.0.jsonl	51
/var/log/fsck_apfs.log	26
/private/var/db/diagnostics/logd.0.log	15
/var/log/fsck_apfs_error.log	14
/Users/user/Library/Logs/DiagnosticReports/banshee_orig-2024-12-12-210846.ips	3
/Users/user/Library/Logs/DiagnosticReports/banshee_orig-2024-12-12-211124.ips	3
/Users/user/Library/Logs/DiagnosticReports/banshee_orig-2024-12-12-211155.ips	3
/private/var/db/diagnostics/shutdown.log	2
/var/log/shutdown_monitor.log	2
/private/var/db/diagnostics/logd_helper.0.log	1
/var/log/daily.out	1
/var/log/wifi.log	1
```
</details><br>
But overall the logs are useless as they only contain 25 events for a specific time range from "2024-12-12 21:45:11" to "2024-12-12 21:45:21" and nothing related to our infostealer.

# References
1. [Beyond the wail: deconstructing the BANSHEE infostealer](https://www.elastic.co/security-labs/beyond-the-wail)
2. [Malware & ThreatsSource Code of $3,000-a-Month macOS Malware ‘Banshee Stealer’ Leaked](https://www.securityweek.com/source-code-of-3000-a-month-macos-malware-banshee-stealer-leaked/)
3. [Jamf. Unified Logging](https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Unified_Logging.html)
4. [Kandji. Mac Logging and the log Command: A Guide for Apple Admins](https://www.kandji.io/blog/mac-logging-and-the-log-command-a-guide-for-apple-admins)
5. [Aftermath. macOS IR Framework](https://github.com/jamf/aftermath)
6. [Google santa. A binary authorization and monitoring system for macOS](https://github.com/google/santa)
7. [A deep dive into macOS TCC.db](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
8. [Original Apple Script from source code](files/tempAppleScript.scpt)