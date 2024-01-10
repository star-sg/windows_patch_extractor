#Extrack All Hyper-V related binary and patch

Param(
    [Parameter(Mandatory=$true)]
    [String]$Path, #path to expand directory
    $Arch = "amd64"
)

$magic = Join-Path $PSScriptRoot "magic.py"

function Compare-Binary($First, $Second)
{

}

function ConvertTo-Forward($Name)
{
    $cmdline
}


if(!(Test-Path -Path $Path))
{
    Write-Host "Given Path: $Path doesn't exist!"
    Exit
}

#Get All Hyper-V Binary Name in patch

$hyperv_dirs  = Get-ChildItem -Path (Get-ChildItem -Path $Path -Filter "*KB*" -Attribute Directory) -Filter "$Arch*hyperv*" -Attribute Directory
$bins = @()

foreach($h in $hyperv_dirs)
{
    if(!(Test-Path -Path (Join-Path $h.FullName "f")))
    {
        Write-Host "No forward patch, skipping... $h"
        continue
    }
    $bins += ((Get-ChildItem -Path (Join-Path $h.FullName "f")))
}

$Path = (Get-Item -Path $Path).FullName

foreach($b in $bins)
{
    if($b.Extension -notlike ".exe" -and $b.Extension -notlike ".dll" -and $b.Extension -notlike ".sys")
    {
        continue
    }
    $cmdline = "$magic -diff $b $Arch $Path"
    Write-Verbose "diff $b"

    $proc = Start-Process "python.exe" -ArgumentList $cmdline -PassThru -NoNewWindow
    Wait-Process -Id $proc.Id


}