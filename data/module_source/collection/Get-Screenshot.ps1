function Get-Screenshot 
{
    param
    (
        [Parameter(Mandatory = $False)]
        [string]
        $Ratio
    )
    Add-Type -Assembly System.Windows.Forms;
    $ScreenBounds = [Windows.Forms.SystemInformation]::VirtualScreen;
    $ScreenshotObject = New-Object Drawing.Bitmap $ScreenBounds.Width, $ScreenBounds.Height;
    $DrawingGraphics = [Drawing.Graphics]::FromImage($ScreenshotObject);
    $DrawingGraphics.CopyFromScreen( $ScreenBounds.Location, [Drawing.Point]::Empty, $ScreenBounds.Size);
    $DrawingGraphics.Dispose();
    $ms = New-Object System.IO.MemoryStream;
    if ($Ratio) {
    	try {
    		$iQual = [convert]::ToInt32($Ratio);
    	} catch {
    		$iQual=80;
    	}
    	if ($iQual -gt 100){
    		$iQual=100;
    	} elseif ($iQual -lt 1){
    		$iQual=1;
    	}
    	$encoderParams = New-Object System.Drawing.Imaging.EncoderParameters;
			$encoderParams.Param[0] = New-Object Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality, $iQual);
			$jpegCodec = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.FormatDescription -eq "JPEG" }
			$ScreenshotObject.save($ms, $jpegCodec, $encoderParams);
		} else {
    	$ScreenshotObject.save($ms, [Drawing.Imaging.ImageFormat]::Png);
    }
    $ScreenshotObject.Dispose();
    [convert]::ToBase64String($ms.ToArray());
}
Get-Screenshot