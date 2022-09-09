$SOURCE_PCAP_DIR = "/home/tz251/hdd/dataset/USTC-TFC2016/1_Pcap"
$DST_PCAP_DIR = "/home/tz251/hdd/dataset/USTC-TFC2016/2_Session"

if ($($args.Count) -ne 1) {
    Write-Host $($args.Count)
    Write-Host "[ERROR] Wrong format of command!"
    Write-Host "[INFO] For Windows: .\1_Pcap2Session.ps1 <TYPE>"
    Write-Host "[INFO] For Linux:   pwsh 1_Pcap2Session.ps1 <TYPE>"
    Write-Host "[INFO] <TYPE>: -f (flow) | -s (session) | -p (packet)"
} 
else {
    if ($($args[0]) -eq "-f") {
        Write-Host "[INFO] Spliting the PCAP file into each flow"
        foreach ($f in Get-ChildItem $($SOURCE_PCAP_DIR) -recurse -Include *.pcap) {
            $new_path = (Convert-Path $f.PSPath).Replace($SOURCE_PCAP_DIR, "").Replace(".pcap", "")
            # For Linux
            mono ./SplitCap.exe -p 50000 -b 50000 -r $f -s flow -o $DST_PCAP_DIR/AllLayers/$($new_path)-ALL
            Get-ChildItem $DST_PCAP_DIR/AllLayers/$($new_path)-ALL | ? { $_.Length -eq 0 } | Remove-Item
            mono ./SplitCap.exe -p 50000 -b 50000 -r $f -s flow -o $DST_PCAP_DIR/L7/$($new_path)-L7 -y L7
            Get-ChildItem $DST_PCAP_DIR/L7/$($new_path)-L7 | ? { $_.Length -eq 0 } | Remove-Item
        }

        # Remove duplicate files
        Write-Host "[INFO] Removing duplicate files"

        # For Linux
        fdupes -rdN $DST_PCAP_DIR/AllLayers/
        fdupes -rdN $DST_PCAP_DIR/L7/
    }
    elseif ($($args[0]) -eq "-s") {
        Write-Host "[INFO] Spliting the PCAP file into each session"
        foreach ($f in Get-ChildItem $SOURCE_PCAP_DIR -recurse -Include *.pcap) {
            $new_path = (Convert-Path $f.PSPath).Replace($SOURCE_PCAP_DIR, "").Replace(".pcap", "")
            # For Linux
            mono ./SplitCap.exe -p 50000 -b 50000 -r $f -o $DST_PCAP_DIR/AllLayers$($new_path)-ALL
            Get-ChildItem $DST_PCAP_DIR/AllLayers$($new_path)-ALL | ? { $_.Length -eq 0 } | Remove-Item
            mono ./SplitCap.exe -p 50000 -b 50000 -r $f -o $DST_PCAP_DIR/L7$($new_path)-L7 -y L7
            Get-ChildItem $DST_PCAP_DIR/L7$($new_path)-L7 | ? { $_.Length -eq 0 } | Remove-Item
        }

        # Remove duplicate files
        Write-Host "[INFO] Removing duplicate files"

        # For Linux
        fdupes -rdN $DST_PCAP_DIR/AllLayers/
        fdupes -rdN $DST_PCAP_DIR/L7/
    
    }
    elseif ($($args[0]) -eq "-p") {
        Write-Host "[INFO] Create folder 'AllLayers_Pkts'"
        if (!(Test-Path -Path $DST_PCAP_DIR/AllLayers_Pkts)) {
            New-Item -Path $DST_PCAP_DIR/ -Name "AllLayers_Pkts" -ItemType "directory"
        }
        Write-Host "[INFO] Spliting the PCAP file into each packet"
        foreach ($f in Get-ChildItem $SOURCE_PCAP_DIR) {
            $new_path = (Convert-Path $f.PSPath).Replace($SOURCE_PCAP_DIR, "").Replace(".pcap", "")
            # For Linux
            if (!(Test-Path -Path $DST_PCAP_DIR/AllLayers_Pkts/$($new_path))) {
                New-Item -Path $DST_PCAP_DIR/AllLayers_Pkts/ -Name $($new_path) -ItemType "directory"
            }
            editcap -c 1 $f $DST_PCAP_DIR/AllLayers_Pkts/$($new_path)/$($new_path).pcap
        }

        # Remove duplicate files
        Write-Host "[INFO] Removing duplicate files"

        # For Linux
        fdupes -rdN $DST_PCAP_DIR/AllLayers_Pkts/
    } 
    else {
        Write-Host "[ERROR] Wrong format of command!"
        Write-Host "[INFO] For Windows: .\1_Pcap2Session.ps1 <TYPE>"
        Write-Host "[INFO] For Linux:   pwsh 1_Pcap2Session.ps1 <TYPE>"
        Write-Host "[INFO] <TYPE>: -f (flow) | -s (session) | -p (packet)"
    }
}
