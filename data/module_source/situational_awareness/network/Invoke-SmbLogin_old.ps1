function Invoke-SMBLogin {
    [CmdletBinding()]
    Param
    (
        [string]$UserName,
        [string]$Password,
		[string]$ComputerName
    )
    if (!($UserName) -or !($Password) -or !($ComputerName)) {
        Write-Warning 'Invoke-SMBLogin: Please specify a username, password and computer.'
    } else {
	
		try{
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$ComputerName)
        $Result=$DS.ValidateCredentials($UserName, $Password)
		
		if ($Result) {
			Write-Verbose "SUCCESS: $Username works with $Password on $ComputerName"
			$out = new-object psobject
			$out | add-member Noteproperty 'ComputerName' $Computer
			$out | add-member Noteproperty 'Username' $Username
			$out | add-member Noteproperty 'Password' $Password
			$out | add-member Noteproperty 'Result' 'Success'
			$out
			
		}
		else {
			Write-Verbose "FAILED:  $Username works with $Password on $ComputerName"
			$out = new-object psobject
			$out | add-member Noteproperty 'ComputerName' $Computer
			$out | add-member Noteproperty 'Username' $Username
			$out | add-member Noteproperty 'Password' $Password
			$out | add-member Noteproperty 'Result' 'Failed'
			$out
		
		}	
		}
		Catch{
		
			if ($_.Exception.Message -like '*network path was not found*'){
			
				Write-Verbose "SUCCESS (Network path not found) : $Username works with $Password on $ComputerName"
				$out = new-object psobject
				$out | add-member Noteproperty 'ComputerName' $Computer
				$out | add-member Noteproperty 'Username' $Username
				$out | add-member Noteproperty 'Password' $Password
				$out | add-member Noteproperty 'Result' 'Success'
				$out
			
			}
			elseif ($_.Exception.Message -like '*Access is Denied*'){
				Write-Verbose "SUCCESS ( No persmision ): $Username works with $Password on $ComputerName"
				$out = new-object psobject
				$out | add-member Noteproperty 'ComputerName' $Computer
				$out | add-member Noteproperty 'Username' $Username
				$out | add-member Noteproperty 'Password' $Password
				$out | add-member Noteproperty 'Result' 'Success'
				$out
			
			}
		}
    }
}