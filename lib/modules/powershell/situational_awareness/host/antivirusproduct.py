from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Get-AntiVirusProduct',

            'Author': ['@mh4x0f', 'Jan Egil Ring'],

            'Description': ('Get antivirus product information.'),

            'Background' : True,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : True,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'http://blog.powershell.no/2011/06/12/use-windows-powershell-to-get-antivirus-product-information/'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                'Description'   :   'Agent to run module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'ComputerName' : {
                'Description'   :   'Computername to run the module on, defaults to localhost.',
                'Required'      :   False,
                'Value'         :   ''
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu
        
        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self, obfuscate=False, obfuscationCommand=""):
        
        script = """
function Get-AntiVirusProduct { 
      [CmdletBinding()] 
      param ( 
      [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)] 
      [Alias('name')] 
      $ComputerName=$env:computername )
      $Query = 'select * from AntiVirusProduct'
      $AntivirusProduct = Get-WmiObject -Namespace 'root\SecurityCenter2' -Query $Query @psboundparameters -ErrorVariable myError -ErrorAction 'SilentlyContinue'
      switch ($AntiVirusProduct.productState) { 
          '262144' {$defstatus = 'Up to date' ;$rtstatus  = 'Disabled'} 
          '262160' {$defstatus = 'Out of date' ;$rtstatus = 'Disabled'} 
          '266240' {$defstatus = 'Up to date' ;$rtstatus  = 'Enabled'} 
          '266256' {$defstatus = 'Out of date' ;$rtstatus = 'Enabled'} 
          '393216' {$defstatus = 'Up to date' ;$rtstatus  = 'Disabled'} 
          '393232' {$defstatus = 'Out of date' ;$rtstatus = 'Disabled'} 
          '393488' {$defstatus = 'Out of date' ;$rtstatus = 'Disabled'} 
          '397312' {$defstatus = 'Up to date' ;$rtstatus  = 'Enabled'} 
          '397328' {$defstatus = 'Out of date' ;$rtstatus = 'Enabled'} 
          '397584' {$defstatus = 'Out of date' ;$rtstatus = 'Enabled'} 
          default {$defstatus = 'Unknown' ;$rtstatus = 'Unknown'} 
          }
      $ht = @{} 
      $ht.Computername = $ComputerName 
      $ht.Name = $AntiVirusProduct.displayName 
      $ht.ProductExecutable = $AntiVirusProduct.pathToSignedProductExe 
      $ht.'Definition Status' = $defstatus 
      $ht.'Real-time Protection Status' = $rtstatus
      New-Object -TypeName PSObject -Property $ht
}

Get-AntiVirusProduct """

        for option,values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])

        script += ' | Out-String | %{$_ + \"`n\"};"`n'+str(self.info["Name"])+' completed!";'
        if obfuscate:
            script = helpers.obfuscate(self.mainMenu.installPath, psScript=script, obfuscationCommand=obfuscationCommand)
        return script
