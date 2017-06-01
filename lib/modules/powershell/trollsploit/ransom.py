$Check = (get-bitlockervolume -mountpoint $ENV:SystemDrive)
$Status = $Check.ProtectionStatus

REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v EnableBDEWithNoTPM /t REG_DWORD /d 1 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseAdvancedStartup /t REG_DWORD /d 1 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseTPM /t REG_DWORD /d 2 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseTPMKey /t REG_DWORD /d 2 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseTPMKeyPIN /t REG_DWORD /d 2 /f


REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v RecoveryKeyMessage /t REG_SZ /d $Message /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /V RecoveryKeyMessageSource /t REG_DWORD /d 2 /f
REG ADD HKLM\SOFTWARE\Policies\Microsoft\FVE /v UseTPMPIN /t REG_DWORD /d 2 /f

$PlainPassword = $Password
$SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force 



if($Status -eq 'Off'){

enable-bitlocker -EncryptionMethod Aes256 -password $securepassword -mountpoint $ENV:SystemDrive  -PasswordProtector -skiphardwaretest -UsedSpaceOnly


add-bitlockerkeyprotector -mountpoint $ENV:SystemDrive -RecoveryKeyProtector -RecoveryKeyPath $ENV:SystemDrive\


if $Restart == 'True' or $Restart == 'true'{
restart-computer
}
}

if ($Status -eq 'On'){
$IDS = $check.KeyProtector.KeyProtectorID

foreach($ID in $IDS){
Remove-BitlockerKeyProtector -Mountpoint $ENV:SystemDrive -KeyProtectorID $ID
}
add-bitlockerkeyprotector -mountpoint $ENV:SystemDrive -PasswordProtector -Password $securepassword
add-bitlockerkeyprotector -mountpoint $ENV:SystemDrive -RecoveryKeyProtector -RecoveryKeyPath $ENV:SystemDrive\
Resume-Bitlocker -MountPoint $ENV:SystemDrive
}