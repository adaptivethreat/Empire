# How To Contribute

Contributions are more than welcome! The more people who contribute to the project the better Empire will be for everyone. Below are a few guidelines for submitting contributions.


## Creating Github Issues

Please first review the existing Empire issues to see if the error was resolved with a fix in the development branch or if we chose not to fix the error for some reason.

The more information you provide in a Github issue the easier it will be for us to track down and fix the problem:

* Please provide the version of Empire you are using.
* Please provide the OS and Python versions that you are using.
* Please describe the expected behavior and the encountered error.
  * The more detail the better!
  * Include any actions taken just prior to the error.
  * Please post a screenshot of the error, a link to a Pastebin dump of the error, or embedded text of the error.
* Any additional information.


## Submitting Modules

* Submit pull requests to the [dev branch](https://github.com/powershellempire/Empire/tree/dev). After testing, changes will be merged to master.
* Base modules on the template at [./modules/template.py](https://github.com/PowerShellEmpire/Empire/blob/dev/lib/modules/template.py). **Note** that for some modules you may need to massage the output to get it into a nicely displayable text format [with Out-String](https://github.com/PowerShellEmpire/Empire/blob/0cbdb165a29e4a65ad8dddf03f6f0e36c33a7350/lib/modules/situational_awareness/network/powerview/get_user.py#L111).
* Cite previous work in the **'Comments'** module section.
* If your script.ps1 logic is large, may be reused by multiple modules, or is updated often, consider implementing the logic in the appropriate **data/module_source/*** directory and [pulling the script contents into the module on tasking](https://github.com/PowerShellEmpire/Empire/blob/0cbdb165a29e4a65ad8dddf03f6f0e36c33a7350/lib/modules/situational_awareness/network/powerview/get_user.py#L85-L95).
* Use [approved PowerShell verbs](https://technet.microsoft.com/en-us/library/ms714428(v=vs.85).aspx) for any functions.
* PowerShell Version 2 compatibility is **STRONGLY** preferred. 
* TEST YOUR MODULE! Be sure to run it from an Empire agent before submitting a pull to ensure everything is working correctly.
* For additional guidelines for your PowerShell code itself, check out the [PowerSploit style guide](https://github.com/PowerShellMafia/PowerSploit/blob/master/README.md).