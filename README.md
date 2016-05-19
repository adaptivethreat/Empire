#Empire

Empire is a pure PowerShell post-exploitation agent built on cryptologically-secure communications and a flexible architecture. Empire implements the ability to run PowerShell agents without needing powershell.exe, rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz, and adaptable communications to evade network detection, all wrapped up in a usability-focused framework. It premiered at [BSidesLV in 2015](https://www.youtube.com/watch?v=Pq9t59w0mUI).

To install, run the ./setup/install.sh script. There's also a [quickstart here](http://www.powershellempire.com/?page_id=110) and full [documentation here](http://www.powershellempire.com/?page_id=83).

Empire relies heavily on the work from several other projects for its underlying functionality. We have tried to call out a few of those people we've interacted with [heavily here](http://www.powershellempire.com/?page_id=2) and have included author/reference link information in the source of each Empire module as appropriate. If we have failed to improperly cite existing or prior work, please let us know.

Empire is developed by [@harmj0y](https://twitter.com/harmj0y), [@sixdub](https://twitter.com/sixdub), and [@enigma0x3](https://twitter.com/enigma0x3).

## New version improved for Red Team assignments

This section details some commands that we added to the Empire agent (agent.ps1) in order to avoid loosing access due to IDS or IPS detection after a target compromission.

The idea is to never expose the IP address of the C&C server used and therefore minimize the impact of a server being blacklisted. The use of proxies thus became paramount in order to only expose spécifics reserved IP addresses.

The following diagram highlights the servers architecture used on our red Team assignment :
![servers architecture](/servers-architecture.jpg)

### Changes made to the Empire agent

The following changes were made to the source code :
* The $Servers variable was an array object and has been changed to a dynamic arrayList.
* The $isServerFixed variable has been added to the agent script.
* This code is added to Send-Message function :
```
# if server id is not fixed we pickup a random id
if ($isServerFixed -eq 0){
 $script:ServerIndex = Get-Random -minimum 0 -maximum $Servers.Count
}
```
* Commands to manage servers has been added to the Invoke-ShellCommand() function (commands are listed in table below)

<table>
<thead>
    <tr>
      <th style="width: 250px">Command</th>
      <th>Description</th>
    </tr>
  </thead>
<tbody>
<tr>
<td><b>sget</b></td>
<td>Sget stands for servers getter. This command asks the agent to return the list of forwarders servers. The output will be a list with the following syntax : "Server[index] : hostname".</td>
</tr>
<tr>
<td><b>sadd http[s]://hostname:port</b></td>
<td>This command tells the agent to append a forwarder to the servers' list.</td>
</tr>
<tr>
<td><b>skill &lt;index&gt;</b></td>
<td>This command takes a server index as input (server index can be obtained with the sget command) and remove the server (not currently in use) from the agent servers' list.</td>
</tr>
<tr>
<td><b>srandom</b></td>
<td>This command enables the randomization of servers' choice. The agent thus randomly  picks an index from the servers' list before each request.</td>
</tr>
<tr>
<td><b>sfix  &lt;index&gt;</b></td>
<td>This command disables randomization of servers' choice. Only server[index] will be used for upcomming requests.</td>
</tr>
<tr>
<td><b>sinfo</b></td>
<td>This command ask the agent to return the list of servers in use and if the radomization is in enabed or not.</td>
</tr>
<tr>
<td><b>askcreds</b></td>
<td>This command simply run the "Get-Credential" powershell command in new process (non-blocking action) and return the user's inputs (usually proper user credentials).</td>
</tr>
</tbody>
</table>

### Bonus feature : Teensy stager
This new stager generates code used by the teensy microcontroller in order to act as a keyboard. It thus run the "cmd.exe" command and execute an Empire launcher.

Path to the specific module : Empire/lib/stagers/teensy.py

## Contribution Rules

Contributions are more than welcome! The more people who contribute to the project the better Empire will be for everyone. Below are a few guidelines for submitting contributions.

* Submit pull requests to the [dev branch](https://github.com/powershellempire/Empire/tree/dev). After testing, changes will be merged to master.
* Base modules on the template at [./modules/template.py](https://github.com/PowerShellEmpire/Empire/blob/dev/lib/modules/template.py). **Note** that for some modules you may need to massage the output to get it into a nicely displayable text format [with Out-String](https://github.com/PowerShellEmpire/Empire/blob/0cbdb165a29e4a65ad8dddf03f6f0e36c33a7350/lib/modules/situational_awareness/network/powerview/get_user.py#L111).
* Cite previous work in the **'Comments'** module section.
* If your script.ps1 logic is large, may be reused by multiple modules, or is updated often, consider implementing the logic in the appropriate **data/module_source/*** directory and [pulling the script contents into the module on tasking](https://github.com/PowerShellEmpire/Empire/blob/0cbdb165a29e4a65ad8dddf03f6f0e36c33a7350/lib/modules/situational_awareness/network/powerview/get_user.py#L85-L95).
* Use [approved PowerShell verbs](https://technet.microsoft.com/en-us/library/ms714428(v=vs.85).aspx) for any functions.
* PowerShell Version 2 compatibility is **STRONGLY** preferred. 
* TEST YOUR MODULE! Be sure to run it from an Empire agent before submitting a pull to ensure everything is working correctly.
* For additional guidelines for your PowerShell code itself, check out the [PowerSploit style guide](https://github.com/PowerShellMafia/PowerSploit/blob/master/README.md).
