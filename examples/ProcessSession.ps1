$SESSIONS_COUNT_LIMIT_MIN = 0
$SESSIONS_COUNT_LIMIT_MAX = 6000
$TRIMED_FILE_LEN = 784

$SOURCE_IMAGE_DIR = "/home/tz251/Desktop/3_Png/AllLayers"
$DST_IMAGE_DIR = "/home/tz251/Desktop/3_Png_processed"

# Arguments
$TYPE = $($args[0])
$SORT = $($args[1])

function processSession($SOURCE_SESSION_DIR) {
    Write-Host "[INFO] If Sessions more than $SESSIONS_COUNT_LIMIT_MAX we only select the largest $SESSIONS_COUNT_LIMIT_MAX."
    Write-Host "[INFO] Finally Selected Sessions:"

    $dirs = Get-ChildItem $SOURCE_SESSION_DIR -Directory
    foreach ($d in $dirs) {
        $files = Get-ChildItem $d.FullName
        $count = $files.count
        if ($count -gt $SESSIONS_COUNT_LIMIT_MIN) {             
            Write-Host "$($d.Name) $count"       
            if ($count -gt $SESSIONS_COUNT_LIMIT_MAX) {
                if ($SORT -eq "-s") {
                    $files = $files | Sort-Object Length -Descending | Select-Object -First $SESSIONS_COUNT_LIMIT_MAX
                }
                elseif ($SORT -eq "-u")  {
                    $files = $files | Select-Object -First $SESSIONS_COUNT_LIMIT_MAX
                }
                $count = $SESSIONS_COUNT_LIMIT_MAX
            }
            $files = $files | Resolve-Path
                
            $path  = "$($DST_IMAGE_DIR)/$($d.Name)"
            New-Item -Path $path -ItemType Directory -Force

            Copy-Item $files -destination $path 
        }
    }

    Write-Host "[INFO] All files will be trimed to $TRIMED_FILE_LEN length and if it's even shorter we'll fill the end with 0x00..."
    
    foreach ($d in Get-ChildItem $DST_IMAGE_DIR  -Directory) {
        New-Item -Path "$($DST_IMAGE_DIR )\$($d.Name)" -ItemType Directory -Force
        foreach ($f in Get-ChildItem $d.fullname) {
            $content = [System.IO.File]::ReadAllBytes($f.FullName)
            $len = $f.length - $TRIMED_FILE_LEN
            if ($len -gt 0) {        
                $content = $content[0..($TRIMED_FILE_LEN - 1)]        
            }
            elseif ($len -lt 0) {        
                $padding = [Byte[]] (,0x00 * ([math]::abs($len)))
                $content = $content += $padding
            }
            Set-Content -Value $content -AsByteStream -Path "$($DST_IMAGE_DIR )\$($d.Name)\$($f.Name)"
        }        
    }
}


if ($($args.Count) -ne 2) {
    Write-Host "[ERROR] Wrong format of command!"
    Write-Host "[INFO] For Windows: .\2_ProcessSession.ps1 <TYPE> <SORT>"
    Write-Host "[INFO] For Linux:   pwsh 2_ProcessSession.ps1 <TYPE>"
    Write-Host "[INFO] <TYPE>: -a (All Layers) | -l (Layer 7) | -p (All Layers per pkts)"
    Write-Host "[INFO] <SORT>: -s (Sorting) | -u (No sorting)"
}
else {    
    if ($TYPE -eq "-a") {
        processSession $SOURCE_IMAGE_DIR
    }
    elseif ($TYPE -eq "-l") {
        processSession $SOURCE_IMAGE_DIR
    }
    elseif ($TYPE -eq "-p") {
        processSession $SOURCE_IMAGE_DIR
    }
    else {
        Write-Host "[ERROR] Wrong format of command!"
        Write-Host "[INFO] For Windows: .\2_ProcessSession.ps1 <TYPE>"
        Write-Host "[INFO] For Linux:   pwsh 2_ProcessSession.ps1 <TYPE>"
        Write-Host "[INFO] <TYPE>: -a (All Layers) | -l (Layer 7) | -p (All Layers per pkts)"
        Write-Host "[INFO] <SORT>: -s (Sorting) | -u (No sorting)"
    }
}