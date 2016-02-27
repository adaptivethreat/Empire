#Empire

Empire is a pure PowerShell post-exploitation agent built on cryptologically-secure
communications and a flexible architecture. Empire implements the ability to run
PowerShell agents without needing powershell.exe, rapidly deployable post-exploitation
modules ranging from key loggers to Mimikatz, and adaptable communications to evade
network detection, all wrapped up in a usability-focused framework. It premiered at
[BSidesLV in 2015][bsides_lv_2015].

To install dependencies, run the ./setup/dependencies.sh script. To setup the database
and cert run ./setup/setup.sh. There's also a [quickstart here][quickstart]
and full [documentation here][documentation].

Empire relies heavily on the work from several other projects for its underlying
functionality. We have tried to call out a few of those people we've interacted with
[heavily here][acknowledgements] and have included author/reference link information
in the source of each Empire module as appropriate. If we have failed to improperly
cite existing or prior work, please let us know.

Empire is developed by [@harmj0y][tw_harmj0y], [@sixdub][tw_sixdub], and [@enigma0x3][tw_enigma0x3].

## Contribution Rules

Contributions are more than welcome! The more people who contribute to the project the
better Empire will be for everyone. Below are a few guidelines for submitting contributions.

* Submit pull requests to the [dev branch][devbranch]. After testing, changes will be merged
to master.
* Base modules on the template at [./modules/template.py][modules_template]. **Note**
that for some modules you may need to massage the output to get it into a nicely displayable
text format [with Out-String][out_string].
* Cite previous work in the **'Comments'** module section.
* If your script.ps1 logic is large, may be reused by multiple modules, or is updated often,
consider implementing the logic in the appropriate **data/module_source/**\* directory and
[pulling the script contents into the module on tasking][example_script_pulling].
* Use [approved PowerShell verbs][ps_verbs] for any functions.
* PowerShell Version 2 compatibility is **STRONGLY** preferred. 
* TEST YOUR MODULE! Be sure to run it from an Empire agent before submitting a pull to
ensure everything is working correctly.
* For additional guidelines for your PowerShell code itself, check out the
[PowerSploit style guide][powersploit_style].


[bsides_lv_2015]: https://www.youtube.com/watch?v=Pq9t59w0mUI
[quickstart]: http://www.powershellempire.com/?page_id=110
[documentation]: http://www.powershellempire.com/?page_id=83 
[acknowledgements]: http://www.powershellempire.com/?page_id=2
[tw_harmj0y]: https://twitter.com/harmj0y
[tw_sixdub]: https://twitter.com/sixdub
[tw_enigma0x3]: https://twitter.com/enigma0x3
[devbranch]: https://github.com/powershellempire/Empire/tree/dev
[modules_template]: https://github.com/PowerShellEmpire/Empire/blob/dev/lib/modules/template.py
[out_string]: https://github.com/PowerShellEmpire/Empire/blob/0cbdb165a29e4a65ad8dddf03f6f0e36c33a7350/lib/modules/situational_awareness/network/powerview/get_user.py#L111
[example_script_pulling]: https://github.com/PowerShellEmpire/Empire/blob/0cbdb165a29e4a65ad8dddf03f6f0e36c33a7350/lib/modules/situational_awareness/network/powerview/get_user.py#L85-L95
[ps_verbs]: https://technet.microsoft.com/en-us/library/ms714428(v=vs.85).aspx
[powersploit_style]: https://github.com/PowerShellMafia/PowerSploit/blob/master/README.md 
