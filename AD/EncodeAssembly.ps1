Function Invoke-EncodeAssembly
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String]
        $binaryPath,

        [Parameter(Mandatory=$true)]
        [String]
        $namespace,

        [String]
        $class = "Program",

        [bool]
        $capture = $false,

        [String]
        $out = "out.txt"
    )


    $bytes = [System.IO.File]::ReadAllBytes("$(pwd)\$binaryPath")
    [System.IO.MemoryStream] $outStream = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GzipStream($outStream, [System.IO.Compression.CompressionMode]::Compress)
    $gzipStream.Write($bytes, 0, $bytes.Length)
    $gzipStream.Close()
    $outStream.Close()
    [byte[]] $outBytes = $outStream.ToArray()
    $b64Zipped = [System.Convert]::ToBase64String($outBytes)
    $b64Zipped | Out-File -NoNewLine -Encoding ASCII .\$out

    $invokePs1 = 'function Invoke-' + $namespace
    $invokePs1 += @'

{

    [CmdletBinding()]
    Param (
        [String]
        $Command = "cmd"
        )

    $b=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("
'@
    $invokePs1 += $b64Zipped
    $invokePs1 += @'
"))
    $decompressed = New-Object IO.Compression.GzipStream($b,[IO.Compression.CoMPressionMode]::DEComPress)
    $out = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $out )
    [byte[]] $byteOutArray = $out.ToArray()

    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)

'@
    if ($capture) {
        $invokePs1 += @'
    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

'@
    }

    $invokePs1 += "    [" + $namespace + "." + $class + ']::Main($Command.Split(" "))'

    if ($capture) {
        $invokePs1 += @'
    
[Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
'@
    }

    $invokePs1 += @'

}
'@
    $outfile = "Invoke-" + $namespace + ".ps1"
    $invokePs1 | Out-File -NoNewLine -Encoding ASCII .\$outfile
}