#Empire

Empire is a pure PowerShell post-exploitation agent built on cryptologically-secure communications and a flexible architecture. Empire implements the ability to run PowerShell agents without needing powershell.exe, rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz, and adaptable communications to evade network detection, all wrapped up in a usability-focused framework. It premiered at BSidesLV in 2015.

To install, run the ./setup/install.sh script. There's also a [quickstart here](http://www.powershellempire.com/?page_id=110) and full [documentation here](http://www.powershellempire.com/?page_id=83).

Empire relies heavily on the work from several other projects for its underlying functionality. We have tried to call out a few of those people we've interacted with [heavily here](http://www.powershellempire.com/?page_id=2) and have included author/reference link information in the source of each Empire module as appropriate. If we have failed to improperly cite existing or prior work, please let us know.

Empire is developed by @harmj0y, @sixdub, and @enigma0x3.

=========================================================================

Install for any system:
python setup/install-all.py
it will install all necessary dependencies files

Start Empire:
 windows: Double click start.bat
 *nix: python empire

 Empire windows version by asmc modify:) 
 Happy hunting~
