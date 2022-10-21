#Elevate Admin rights
Add-Type -AssemblyName System.Windows.Forms

$ErrorActionPreference = 'SilentlyContinue'
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

Clear-Host
$programs = winget list -q `"`"

$iterator = 0
foreach ($program in $programs) {
    $splitedprograms = $program -split " "
    #Write-Output $splitedprograms
    if ($splitedprograms.Length -eq 1) {
        $right_line = $iterator - 1
        exit
    }
    $iterator += 1
}
$right_line
$line = $programs[$right_line]

$columnnames = @()

$value = "" | Select-Object Name,start,length
$value.start = 0

$last_char = " "

for ($i = 0; $i -lt $line.Length; $i++) {
    $part = $line.Substring($i)
    if (($last_char -eq " ") -and ($part[0] -eq " ")) {
        $value.length += 1
    } elseif (($last_char -eq " ") -and !($part[0] -eq " ")) {
        $value.length = $i - $value.start

        if (!($value.start -eq $value.length)) {
            $columnnames += $value
        }
        $value = "" | Select-Object Name,start,length
        $value.name += $part[0]
        $value.start = $i
        $value.length = 0

    } elseif (!($last_char -eq " ") -and !($part[0] -eq " ")) {
        $value.name += $part[0]
        $value.length += 1
    } elseif (!($last_char -eq " ") -and ($part[0] -eq " ")) {
        $value.length += 1
    }
    $last_char = $part[0]
}

Write-Output $columnnames | Format-Table


$output = @{}
$value = "" | Select-Object "Name, Id, Version, Source"
$value.name = "Name"
$value.start = 0
$value.length = 50
$output += $value

#pause




$programs = winget list -q `"`"

$namestart = 0
$namelength = 0
$idstart = 0
$idlength = 0
$versionstart = 0
$versionlength = 0
$Sourcestart = 0
$unneeded_to_check= @(
    "SDK"
    "Service"
    "add-on"
    "effect"
    "lighting"
    "Live"
    "SSD"
    "RGB"
    "Online"
    "Services"
    "Framework"
    "Motherboard"
    "Driver"
    "Audio"
    "HD"
    "x64"
    "Lite"
    "High"
    "Definition"
    "V"
    "DRAM"
    "Graphics"
    "M2"
)

foreach ($program in $programs) {

    if ($program.StartsWith("Name")) {
        $namestart = 0
        $namelength = 0
        #write-Output $program.Substring($namelength)
        while ( !($program.Substring($namestart,$namelength).EndsWith("Id"))) {
            $namelength = $namelength + 1
        }
        $namelength = $namelength - 2
        $idstart = $namestart + $namelength
        $idlength = 0

        while ( !($program.Substring($idstart,$idlength).EndsWith("Version")) ) {
            #Write-Output $program.Substring($idstart,$idlength)
            $idlength = $idlength + 1
        }
        $idlength = $idlength - 7
        $versionstart = $idstart + $idlength
        $versionlength = 0
        while (!($program.Substring($versionstart,$versionlength).EndsWith("Source"))) {
            #Write-Output $program.Substring($versionstart,$versionlength)
            $versionlength = $versionlength + 1
        }

        $versionlength  = $versionlength - 6
        $Sourcestart = $versionstart + $versionlength

    }
    #Ohne die Werte muss man gar nicht anfangen

    $programname = $program.Substring($namestart,$namelength).Trim()
    $programid = $program.Substring($idstart,$idlength).Trim()
    if ($programid.Substring(1,1) -eq " ") {
        $programid = $programid.Substring(2)
    }
    $programversion = $program.Substring($versionstart,$versionlength).Trim()
    if ($programversion.Substring(1,1) -eq " ") {
        $programversion = $programversion.Substring(2)
    }
    $programsource = $program.Substring($Sourcestart).Trim()

    if ( $programname.Length -lt 3 -or $programid.Length -lt 3 -or $programversion.Length -lt 3 -or $programname.StartsWith("-")){
        #Write-Output "Programname: $($programname)"
        #Write-Output "Programnid: $($programid)"
        #Write-Output "Programnversion: $($programversion)"

    } else {
        Write-Output "Programmname: $($programname)"
        Write-Output ""
        Write-Output "ProgrammID: $($programid)"
        Write-Output ""
        Write-Output "Programmversion: $($programversion)"
        Write-Output ""
        Write-Output "Source: $($programsource)"
        Write-Output ""

        $checked = $false

        #Steam Apps ignoriere ich
        if ($programid.StartsWith("Steam App")) {
            Clear-Host
            continue
        }

        if ($programid.Contains("_")) {
            $checked = $true
            $parts = $programid.split("_")
            foreach ($part in $parts) {
                if (!($part.StartsWith("{") -or $unneeded_to_check.Contains($part))) {
                    $responce = winget search --id $part
                    if (!($responce -eq "No package found matching input criteria.")) {
                        Write-Output ""
                        Write-Output "Suche nach: --id $($part)"
                        $responce
                        #winget search --id $part   
                    }
                }
            }
        }

        if ($programid.StartsWith("{")) {
            $checked = $true
            $responce = winget search $programname
            if (!($responce -eq "No package found matching input criteria.")) {
                Write-Output "ProgrammID startet mit {"
                Write-Output "Das kann bedeuten das die Updates nicht verfuegbar sind hierrueber"
                Write-Output ""
                Write-Output "Suche nach: $($programname)"
                #winget search $programname
                $responce
            }

            $parts = $programname.Split(" ")
            foreach ($part in $parts) {
                if (!($part.StartsWith("{") -or $unneeded_to_check.Contains($part))) {
                    $responce = winget search $part
                    if (!($responce -eq "No package found matching input criteria.")) {
                        Write-Output "Suche nach: $($part)"
                        Write-Output ""
                        #winget search $part
                        $responce
                    }
                }
            }
        }
        if ($programsource -eq ""){
            $checked = $true
            $responce = winget search --id $programname
            if (!($responce -eq "No package found matching input criteria.")) {
                Write-Output ""
                Write-Output "Programsource ist leer."
                Write-Output "Das kann bedeuten das die Updates nicht verfuegbar sind hierrueber"
                Write-Output ""
                Write-Output "Suche nach: --id $($programid)"
                #winget search --id $programname
                $responce
            }

            $responce = winget search $programname
            if (!($responce -eq "No package found matching input criteria.")) {
                Write-Output ""
                Write-Output "Suche nach: $($programname)"
                #winget search $programname
                $responce
            }
        }
        if (!($checked)) {
            Clear-Host
            continue
        }

        $Answer = $null
        do {
            Write-Output ""
            $Answer = Read-Host -Prompt 'Ist das Programm richtig erfasst worden?(y/n)'
        }
        until ($Answer -match "[yYnN]")
        Clear-Host
        $int = $int + 1
    }
    #TODO bei programmen bei dennen nichts gefundenwurde einfach skippen ohne auswahl
}

$Answer = "Stop"
Do {
    $Answer = Read-Host -Prompt 'Programm ist vorbei. Enter zum Vortfahren'
}
Until ( $Answer -eq "" )
