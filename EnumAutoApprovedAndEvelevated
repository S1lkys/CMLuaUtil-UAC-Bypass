<#
.SYNOPSIS
    Enhanced Auto-Elevated COM Object Enumerator with DLL Export Analysis
.DESCRIPTION
    Finds auto-elevated COM objects and extracts DLL exports for analysis
#>

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.IO;

public class PEExportReader
{
    public static string[] GetExports(string dllPath)
    {
        List<string> exports = new List<string>();
        
        try
        {
            if (!File.Exists(dllPath))
                return new string[] { "[File not found]" };

            byte[] fileBytes = File.ReadAllBytes(dllPath);
            
            if (fileBytes.Length < 64)
                return new string[] { "[Invalid PE]" };

            ushort dosMagic = BitConverter.ToUInt16(fileBytes, 0);
            if (dosMagic != 0x5A4D)
                return new string[] { "[Not a PE file]" };

            int peOffset = BitConverter.ToInt32(fileBytes, 60);
            
            if (peOffset + 4 > fileBytes.Length)
                return new string[] { "[Invalid PE header]" };

            uint peSignature = BitConverter.ToUInt32(fileBytes, peOffset);
            if (peSignature != 0x00004550)
                return new string[] { "[Invalid PE signature]" };

            int coffOffset = peOffset + 4;
            ushort numberOfSections = BitConverter.ToUInt16(fileBytes, coffOffset + 2);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(fileBytes, coffOffset + 16);

            int optionalOffset = coffOffset + 20;
            ushort magic = BitConverter.ToUInt16(fileBytes, optionalOffset);
            
            bool is64Bit = (magic == 0x20b);
            
            int exportDirRVA;
            int exportDirSize;
            
            if (is64Bit)
            {
                exportDirRVA = BitConverter.ToInt32(fileBytes, optionalOffset + 112);
                exportDirSize = BitConverter.ToInt32(fileBytes, optionalOffset + 116);
            }
            else
            {
                exportDirRVA = BitConverter.ToInt32(fileBytes, optionalOffset + 96);
                exportDirSize = BitConverter.ToInt32(fileBytes, optionalOffset + 100);
            }

            if (exportDirRVA == 0 || exportDirSize == 0)
                return new string[] { "[No exports]" };

            int sectionOffset = optionalOffset + sizeOfOptionalHeader;
            int exportFileOffset = 0;
            
            for (int i = 0; i < numberOfSections; i++)
            {
                int secOffset = sectionOffset + (i * 40);
                uint virtualSize = BitConverter.ToUInt32(fileBytes, secOffset + 8);
                uint virtualAddress = BitConverter.ToUInt32(fileBytes, secOffset + 12);
                uint rawDataPtr = BitConverter.ToUInt32(fileBytes, secOffset + 20);

                if (exportDirRVA >= virtualAddress && exportDirRVA < virtualAddress + virtualSize)
                {
                    exportFileOffset = (int)(exportDirRVA - virtualAddress + rawDataPtr);
                    break;
                }
            }

            if (exportFileOffset == 0 || exportFileOffset + 40 > fileBytes.Length)
                return new string[] { "[Export directory not found]" };

            uint numberOfNames = BitConverter.ToUInt32(fileBytes, exportFileOffset + 24);
            uint addressOfNames = BitConverter.ToUInt32(fileBytes, exportFileOffset + 32);

            int namesFileOffset = 0;
            for (int i = 0; i < numberOfSections; i++)
            {
                int secOffset = sectionOffset + (i * 40);
                uint virtualSize = BitConverter.ToUInt32(fileBytes, secOffset + 8);
                uint virtualAddress = BitConverter.ToUInt32(fileBytes, secOffset + 12);
                uint rawDataPtr = BitConverter.ToUInt32(fileBytes, secOffset + 20);

                if (addressOfNames >= virtualAddress && addressOfNames < virtualAddress + virtualSize)
                {
                    namesFileOffset = (int)(addressOfNames - virtualAddress + rawDataPtr);
                    break;
                }
            }

            if (namesFileOffset == 0)
                return new string[] { "[Names array not found]" };

            for (uint i = 0; i < numberOfNames && i < 500; i++)
            {
                if (namesFileOffset + (i * 4) + 4 > fileBytes.Length)
                    break;

                uint nameRVA = BitConverter.ToUInt32(fileBytes, namesFileOffset + (int)(i * 4));
                
                int nameFileOffset = 0;
                for (int s = 0; s < numberOfSections; s++)
                {
                    int secOffset = sectionOffset + (s * 40);
                    uint virtualSize = BitConverter.ToUInt32(fileBytes, secOffset + 8);
                    uint virtualAddress = BitConverter.ToUInt32(fileBytes, secOffset + 12);
                    uint rawDataPtr = BitConverter.ToUInt32(fileBytes, secOffset + 20);

                    if (nameRVA >= virtualAddress && nameRVA < virtualAddress + virtualSize)
                    {
                        nameFileOffset = (int)(nameRVA - virtualAddress + rawDataPtr);
                        break;
                    }
                }

                if (nameFileOffset > 0 && nameFileOffset < fileBytes.Length)
                {
                    List<byte> nameBytes = new List<byte>();
                    int pos = nameFileOffset;
                    while (pos < fileBytes.Length && fileBytes[pos] != 0 && nameBytes.Count < 256)
                    {
                        nameBytes.Add(fileBytes[pos]);
                        pos++;
                    }
                    
                    if (nameBytes.Count > 0)
                    {
                        string name = System.Text.Encoding.ASCII.GetString(nameBytes.ToArray());
                        exports.Add(name);
                    }
                }
            }

            if (exports.Count == 0)
                return new string[] { "[No named exports]" };

            exports.Sort();
            return exports.ToArray();
        }
        catch (Exception ex)
        {
            return new string[] { "[Error: " + ex.Message + "]" };
        }
    }
}
"@

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Get-DLLExports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DLLPath
    )
    
    $cleanPath = $DLLPath -replace '"', ''
    $cleanPath = $cleanPath -replace ' /.*$', ''
    $cleanPath = $cleanPath -replace ' -.*$', ''
    $cleanPath = $cleanPath.Trim()
    $cleanPath = [Environment]::ExpandEnvironmentVariables($cleanPath)
    
    if ($cleanPath -match '\\system32\\' -and -not (Test-Path $cleanPath)) {
        $altPath = $cleanPath -replace '\\system32\\', '\SysWOW64\'
        if (Test-Path $altPath) {
            $cleanPath = $altPath
        }
    }
    
    if (-not (Test-Path $cleanPath)) {
        return @("[File not found: $cleanPath]")
    }
    
    try {
        $exports = [PEExportReader]::GetExports($cleanPath)
        return $exports
    } catch {
        return @("[Error reading exports: $($_.Exception.Message)]")
    }
}

function Get-COMObjectDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$CLSID,
        [switch]$IncludeExports
    )
    
    $clsidBasePath = "HKLM:\SOFTWARE\Classes\CLSID"
    $clsidPath = Join-Path $clsidBasePath $CLSID
    
    if (-not (Test-Path $clsidPath)) {
        return $null
    }
    
    $comName = (Get-ItemProperty -Path $clsidPath -ErrorAction SilentlyContinue).'(default)'
    if ([string]::IsNullOrEmpty($comName)) {
        $comName = "Unknown"
    }
    
    $elevationPath = Join-Path $clsidPath "Elevation"
    $elevationEnabled = $false
    $iconReference = "N/A"
    
    if (Test-Path $elevationPath) {
        $elevationData = Get-ItemProperty -Path $elevationPath -ErrorAction SilentlyContinue
        if ($null -ne $elevationData.Enabled) {
            $elevationEnabled = ($elevationData.Enabled -eq 1)
        }
        if ($null -ne $elevationData.IconReference) {
            $iconReference = $elevationData.IconReference
        }
    }
    
    $autoApproved = $true
    
    $server = "N/A"
    $serverType = "N/A"
    
    $localServerPath = Join-Path $clsidPath "LocalServer32"
    $inprocServerPath = Join-Path $clsidPath "InprocServer32"
    
    if (Test-Path $localServerPath) {
        $server = (Get-ItemProperty -Path $localServerPath -ErrorAction SilentlyContinue).'(default)'
        $serverType = "LocalServer32"
    } elseif (Test-Path $inprocServerPath) {
        $server = (Get-ItemProperty -Path $inprocServerPath -ErrorAction SilentlyContinue).'(default)'
        $serverType = "InprocServer32"
    }
    
    $exports = @()
    $exportCount = 0
    
    if ($IncludeExports -and $server -ne "N/A") {
        if ($server -match '\.(dll|exe)') {
            $exports = Get-DLLExports -DLLPath $server
            if ($exports.Count -gt 0 -and $exports[0] -notmatch '^\[') {
                $exportCount = $exports.Count
            }
        }
    }
    
    $typeLibPath = Join-Path $clsidPath "TypeLib"
    $typeLib = "N/A"
    if (Test-Path $typeLibPath) {
        $typeLib = (Get-ItemProperty -Path $typeLibPath -ErrorAction SilentlyContinue).'(default)'
    }
    
    return [PSCustomObject]@{
        CLSID = $CLSID
        Name = $comName
        AutoApproved = $autoApproved
        ElevationEnabled = $elevationEnabled
        IconReference = $iconReference
        Server = $server
        ServerType = $serverType
        TypeLib = $typeLib
        Exports = $exports
        ExportCount = $exportCount
    }
}

function Get-AutoElevatedCOMObjects {
    [CmdletBinding()]
    param(
        [switch]$ExportCSV,
        [switch]$ExportHTML,
        [switch]$ScanAllCLSIDs,
        [string]$OutputPath = "AutoElevatedCOM"
    )
    
    Write-Host "[*] Auto-Elevated COM Enumeration with DLL Exports..." -ForegroundColor Cyan
    Write-Host ""
    
    $results = [System.Collections.ArrayList]::new()
    $processedCLSIDs = @{}
    
    # Methode 1: COMAutoApprovalList (primaere Quelle)
    $autoApprovalPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList"
    
    if (Test-Path $autoApprovalPath) {
        Write-Host "[+] Found COMAutoApprovalList" -ForegroundColor Green
        
        $autoApprovedCLSIDs = Get-ItemProperty -Path $autoApprovalPath -ErrorAction SilentlyContinue
        $clsidList = $autoApprovedCLSIDs.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" -and $_.Value -eq 1 }
        
        $total = @($clsidList).Count
        $current = 0
        
        Write-Host "[*] Processing $total auto-approved CLSIDs..." -ForegroundColor White
        
        foreach ($property in $clsidList) {
            $current++
            $clsid = $property.Name
            
            Write-Progress -Activity "Processing Auto-Approved CLSIDs" -Status "$current of $total - $clsid" -PercentComplete (($current / $total) * 100)
            
            if (-not $processedCLSIDs.ContainsKey($clsid)) {
                $obj = Get-COMObjectDetails -CLSID $clsid -IncludeExports
                if ($null -ne $obj) {
                    [void]$results.Add($obj)
                    $processedCLSIDs[$clsid] = $true
                    Write-Host "`r[+] $current/$total - $($obj.Name)" -ForegroundColor Green
                }
            }
        }
        
        Write-Progress -Activity "Processing Auto-Approved CLSIDs" -Completed
    } else {
        Write-Host "[!] COMAutoApprovalList not found at expected path" -ForegroundColor Red
        Write-Host "[!] Tried: $autoApprovalPath" -ForegroundColor Yellow
    }
    
    # Methode 2: Bekannte exploitable CLSIDs
    Write-Host "`n[*] Checking known exploitable CLSIDs..." -ForegroundColor Cyan
    
    $knownCLSIDs = @(
        "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}",
        "{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}",
        "{1F87137D-0E7C-44D5-8C73-4EFFB68962F2}",
        "{17CCA47D-DAE5-4E4A-AC42-CC54E28F334A}",
        "{0A29FF9E-7F9C-4437-8B11-F424491E3931}",
        "{FCC74B77-EC3E-4DD8-A80B-008A702075A9}"
    )
    
    foreach ($clsid in $knownCLSIDs) {
        if (-not $processedCLSIDs.ContainsKey($clsid)) {
            $obj = Get-COMObjectDetails -CLSID $clsid -IncludeExports
            if ($null -ne $obj) {
                [void]$results.Add($obj)
                $processedCLSIDs[$clsid] = $true
                Write-Host "[+] Known exploitable: $clsid - $($obj.Name)" -ForegroundColor Yellow
            }
        }
    }
    
    # Methode 3: Optional - Alle CLSIDs scannen (langsam!)
    if ($ScanAllCLSIDs) {
        Write-Host "`n[*] Scanning ALL CLSIDs for Elevation flag (this takes a while)..." -ForegroundColor Yellow
        
        $clsidBasePath = "HKLM:\SOFTWARE\Classes\CLSID"
        $allCLSIDs = Get-ChildItem -Path $clsidBasePath -ErrorAction SilentlyContinue
        $total = $allCLSIDs.Count
        $current = 0
        
        Write-Host "[*] Found $total CLSIDs to scan..." -ForegroundColor White
        
        foreach ($clsidKey in $allCLSIDs) {
            $current++
            
            if ($current % 500 -eq 0) {
                Write-Progress -Activity "Scanning ALL CLSIDs" -Status "$current of $total" -PercentComplete (($current / $total) * 100)
            }
            
            $clsid = $clsidKey.PSChildName
            
            if ($processedCLSIDs.ContainsKey($clsid)) { continue }
            
            $elevationPath = Join-Path $clsidKey.PSPath "Elevation"
            
            if (Test-Path $elevationPath) {
                $elevationData = Get-ItemProperty -Path $elevationPath -ErrorAction SilentlyContinue
                
                if ($null -ne $elevationData.Enabled -and $elevationData.Enabled -eq 1) {
                    $obj = Get-COMObjectDetails -CLSID $clsid -IncludeExports
                    if ($null -ne $obj) {
                        [void]$results.Add($obj)
                        $processedCLSIDs[$clsid] = $true
                        Write-Host "`r[+] Found elevated: $clsid - $($obj.Name)" -ForegroundColor Magenta
                    }
                }
            }
        }
        
        Write-Progress -Activity "Scanning ALL CLSIDs" -Completed
    }
    
    Write-Host ""
    Write-Host "[*] Summary:" -ForegroundColor Cyan
    Write-Host "    Total CLSIDs found: $($results.Count)" -ForegroundColor White
    Write-Host "    With Elevation Enabled: $(($results | Where-Object { $_.ElevationEnabled }).Count)" -ForegroundColor White
    Write-Host "    With DLL Exports: $(($results | Where-Object { $_.ExportCount -gt 0 }).Count)" -ForegroundColor White
    Write-Host ""
    
    $sortedResults = $results | Sort-Object -Property Name
    
    if ($ExportCSV) {
        $csvPath = "$OutputPath.csv"
        $sortedResults | Select-Object CLSID, Name, AutoApproved, ElevationEnabled, Server, ServerType, ExportCount | 
            Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "[+] CSV exported to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportHTML) {
        $htmlPath = "$OutputPath.html"
        Export-HTMLReport -Results $sortedResults -OutputPath $htmlPath
        Write-Host "[+] HTML Report exported to: $htmlPath" -ForegroundColor Green
    }
    
    return $sortedResults
}

function Export-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Results,
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $hostname = $env:COMPUTERNAME
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auto-Elevated COM Objects Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #0f3460;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
        }
        h1 { color: #00d9ff; font-size: 2em; margin-bottom: 10px; }
        .meta-info { color: #888; font-size: 0.9em; }
        .meta-info span { margin-right: 20px; }
        .stats { display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }
        .stat-card {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #0f3460;
            border-radius: 8px;
            padding: 20px;
            flex: 1;
            min-width: 150px;
            text-align: center;
        }
        .stat-card h3 { color: #888; font-size: 0.9em; margin-bottom: 5px; }
        .stat-card .value { font-size: 2em; font-weight: bold; color: #00d9ff; }
        .stat-card.warning .value { color: #ff6b6b; }
        .stat-card.success .value { color: #51cf66; }
        .search-box { margin-bottom: 20px; }
        .search-box input {
            width: 100%;
            padding: 12px 20px;
            border: 1px solid #0f3460;
            border-radius: 8px;
            background: #1a1a2e;
            color: #e0e0e0;
            font-size: 1em;
        }
        .search-box input:focus {
            outline: none;
            border-color: #00d9ff;
        }
        .btn-group { margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }
        .btn {
            background: #0f3460;
            color: #00d9ff;
            border: 1px solid #00d9ff;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
        }
        .btn:hover { background: rgba(0, 217, 255, 0.1); }
        .com-object {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #0f3460;
            border-radius: 8px;
            margin-bottom: 10px;
            overflow: hidden;
        }
        .com-object:hover { border-color: #00d9ff; }
        .com-header {
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .com-header:hover { background: rgba(0, 217, 255, 0.05); }
        .com-name { font-weight: 600; color: #fff; font-size: 1.1em; }
        .com-clsid { color: #888; font-family: 'Consolas', monospace; font-size: 0.85em; }
        .badges { display: flex; gap: 8px; flex-wrap: wrap; }
        .badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge.elevated { background: rgba(255, 107, 107, 0.2); color: #ff6b6b; border: 1px solid #ff6b6b; }
        .badge.approved { background: rgba(255, 193, 7, 0.2); color: #ffc107; border: 1px solid #ffc107; }
        .badge.exports { background: rgba(81, 207, 102, 0.2); color: #51cf66; border: 1px solid #51cf66; }
        .expand-icon { color: #00d9ff; transition: transform 0.3s ease; }
        .com-object.expanded .expand-icon { transform: rotate(180deg); }
        .com-details {
            display: none;
            padding: 0 20px 20px 20px;
            border-top: 1px solid #0f3460;
        }
        .com-object.expanded .com-details { display: block; }
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .detail-item {
            background: rgba(0, 0, 0, 0.2);
            padding: 12px 15px;
            border-radius: 6px;
        }
        .detail-item label { color: #888; font-size: 0.8em; display: block; margin-bottom: 5px; }
        .detail-item .value {
            color: #e0e0e0;
            font-family: 'Consolas', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        .exports-section { margin-top: 15px; }
        .exports-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 15px;
            background: rgba(81, 207, 102, 0.1);
            border: 1px solid rgba(81, 207, 102, 0.3);
            border-radius: 6px 6px 0 0;
            cursor: pointer;
        }
        .exports-header:hover { background: rgba(81, 207, 102, 0.15); }
        .exports-header h4 { color: #51cf66; font-size: 0.9em; }
        .exports-list {
            display: none;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(81, 207, 102, 0.3);
            border-top: none;
            border-radius: 0 0 6px 6px;
            max-height: 400px;
            overflow-y: auto;
        }
        .exports-section.expanded .exports-list { display: block; }
        .export-item {
            padding: 8px 15px;
            font-family: 'Consolas', monospace;
            font-size: 0.85em;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            color: #aaa;
        }
        .export-item:last-child { border-bottom: none; }
        .export-item:hover { background: rgba(81, 207, 102, 0.1); color: #51cf66; }
        .export-item.interesting { color: #ff6b6b; font-weight: 600; }
        .no-exports { padding: 15px; color: #666; font-style: italic; text-align: center; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1a1a2e; }
        ::-webkit-scrollbar-thumb { background: #0f3460; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Auto-Elevated COM Objects Report</h1>
            <div class="meta-info">
                <span>Host: $hostname</span>
                <span>Generated: $timestamp</span>
            </div>
        </header>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Objects</h3>
                <div class="value">$($Results.Count)</div>
            </div>
            <div class="stat-card warning">
                <h3>Elevation Enabled</h3>
                <div class="value">$(($Results | Where-Object { $_.ElevationEnabled }).Count)</div>
            </div>
            <div class="stat-card">
                <h3>Auto-Approved</h3>
                <div class="value">$(($Results | Where-Object { $_.AutoApproved }).Count)</div>
            </div>
            <div class="stat-card success">
                <h3>With Exports</h3>
                <div class="value">$(($Results | Where-Object { $_.ExportCount -gt 0 }).Count)</div>
            </div>
        </div>
        
        <div class="search-box">
            <input type="text" id="searchInput" placeholder="Search by name, CLSID, or export function..." onkeyup="filterObjects()">
        </div>
        
        <div class="btn-group">
            <button class="btn" onclick="toggleAll()">Expand/Collapse All</button>
            <button class="btn" onclick="filterByExports()">Show With Exports Only</button>
            <button class="btn" onclick="filterByElevated()">Show Elevated Only</button>
            <button class="btn" onclick="clearFilter()">Clear Filter</button>
        </div>
        
        <div id="objects-container">
"@

    foreach ($obj in $Results) {
        $badges = ""
        if ($obj.ElevationEnabled) {
            $badges += '<span class="badge elevated">Elevated</span>'
        }
        if ($obj.AutoApproved) {
            $badges += '<span class="badge approved">Auto-Approved</span>'
        }
        if ($obj.ExportCount -gt 0) {
            $badges += "<span class=`"badge exports`">$($obj.ExportCount) Exports</span>"
        }
        
        $serverDisplay = if ($obj.Server -ne "N/A") { $obj.Server } else { "Not available" }
        
        $exportsHtml = ""
        if ($obj.Exports.Count -gt 0 -and $obj.Exports[0] -notmatch '^\[') {
            $exportItems = ""
            $interestingPatterns = @('Exec', 'Run', 'Launch', 'Shell', 'Create', 'Load', 'Inject', 'Write', 'Delete', 'Registry', 'Process', 'Command', 'Elevate', 'Admin', 'Privilege')
            
            foreach ($export in $obj.Exports) {
                $isInteresting = $false
                foreach ($pattern in $interestingPatterns) {
                    if ($export -match $pattern) {
                        $isInteresting = $true
                        break
                    }
                }
                $class = if ($isInteresting) { 'export-item interesting' } else { 'export-item' }
                $exportItems += "<div class=`"$class`">$(ConvertTo-HtmlEncoded $export)</div>"
            }
            
            $exportsHtml = @"
            <div class="exports-section" onclick="toggleExports(event, this)">
                <div class="exports-header">
                    <h4>DLL Exports ($($obj.ExportCount))</h4>
                    <span class="expand-icon">&#9660;</span>
                </div>
                <div class="exports-list">
                    $exportItems
                </div>
            </div>
"@
        } elseif ($obj.Exports.Count -gt 0) {
            $exportsHtml = @"
            <div class="exports-section">
                <div class="no-exports">$(ConvertTo-HtmlEncoded $obj.Exports[0])</div>
            </div>
"@
        }
        
        $elevated = if ($obj.ElevationEnabled) { "true" } else { "false" }
        $hasExports = if ($obj.ExportCount -gt 0) { "true" } else { "false" }
        
        $html += @"
            <div class="com-object" data-name="$(ConvertTo-HtmlEncoded $obj.Name.ToLower())" data-clsid="$($obj.CLSID.ToLower())" data-exports="$(ConvertTo-HtmlEncoded ($obj.Exports -join ' ').ToLower())" data-elevated="$elevated" data-hasexports="$hasExports">
                <div class="com-header" onclick="toggleObject(this.parentElement)">
                    <div>
                        <div class="com-name">$(ConvertTo-HtmlEncoded $obj.Name)</div>
                        <div class="com-clsid">$($obj.CLSID)</div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <div class="badges">$badges</div>
                        <span class="expand-icon">&#9660;</span>
                    </div>
                </div>
                <div class="com-details">
                    <div class="detail-grid">
                        <div class="detail-item">
                            <label>Server Type</label>
                            <div class="value">$($obj.ServerType)</div>
                        </div>
                        <div class="detail-item">
                            <label>Server Path</label>
                            <div class="value">$(ConvertTo-HtmlEncoded $serverDisplay)</div>
                        </div>
                        <div class="detail-item">
                            <label>Elevation Enabled</label>
                            <div class="value">$($obj.ElevationEnabled)</div>
                        </div>
                        <div class="detail-item">
                            <label>Auto-Approved</label>
                            <div class="value">$($obj.AutoApproved)</div>
                        </div>
                    </div>
                    $exportsHtml
                </div>
            </div>
"@
    }

    $html += @"
        </div>
    </div>
    
    <script>
        function toggleObject(element) {
            element.classList.toggle('expanded');
        }
        
        function toggleExports(event, element) {
            event.stopPropagation();
            element.classList.toggle('expanded');
        }
        
        function toggleAll() {
            const objects = document.querySelectorAll('.com-object');
            const allExpanded = Array.from(objects).every(obj => obj.classList.contains('expanded'));
            objects.forEach(obj => {
                if (allExpanded) obj.classList.remove('expanded');
                else obj.classList.add('expanded');
            });
        }
        
        function filterObjects() {
            const filter = document.getElementById('searchInput').value.toLowerCase();
            document.querySelectorAll('.com-object').forEach(obj => {
                const name = obj.getAttribute('data-name') || '';
                const clsid = obj.getAttribute('data-clsid') || '';
                const exports = obj.getAttribute('data-exports') || '';
                obj.style.display = (name.includes(filter) || clsid.includes(filter) || exports.includes(filter)) ? '' : 'none';
            });
        }
        
        function filterByExports() {
            document.querySelectorAll('.com-object').forEach(obj => {
                obj.style.display = obj.getAttribute('data-hasexports') === 'true' ? '' : 'none';
            });
        }
        
        function filterByElevated() {
            document.querySelectorAll('.com-object').forEach(obj => {
                obj.style.display = obj.getAttribute('data-elevated') === 'true' ? '' : 'none';
            });
        }
        
        function clearFilter() {
            document.getElementById('searchInput').value = '';
            document.querySelectorAll('.com-object').forEach(obj => obj.style.display = '');
        }
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

# Main Menu
Clear-Host
Write-Host @"
+-----------------------------------------------------------+
|     Auto-Elevated COM Object Enumerator v4.0              |
|           With DLL Export Analysis                        |
+-----------------------------------------------------------+
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "Select an option:" -ForegroundColor Yellow
Write-Host "  1) Enumerate Auto-Approved COM Objects (fast)" -ForegroundColor White
Write-Host "  2) Export to HTML Report" -ForegroundColor White
Write-Host "  3) Export to CSV and HTML" -ForegroundColor White
Write-Host "  4) Full scan including ALL CLSIDs (slow)" -ForegroundColor White
Write-Host "  0) Exit" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Enter choice"

switch ($choice) {
    "1" { 
        Get-AutoElevatedCOMObjects 
    }
    "2" { 
        $path = Read-Host "Output path without extension (default: AutoElevatedCOM)"
        if ([string]::IsNullOrEmpty($path)) { $path = "AutoElevatedCOM" }
        Get-AutoElevatedCOMObjects -ExportHTML -OutputPath $path 
    }
    "3" { 
        $path = Read-Host "Output path without extension (default: AutoElevatedCOM)"
        if ([string]::IsNullOrEmpty($path)) { $path = "AutoElevatedCOM" }
        Get-AutoElevatedCOMObjects -ExportCSV -ExportHTML -OutputPath $path 
    }
    "4" { 
        $path = Read-Host "Output path without extension (default: AutoElevatedCOM)"
        if ([string]::IsNullOrEmpty($path)) { $path = "AutoElevatedCOM" }
        Get-AutoElevatedCOMObjects -ExportCSV -ExportHTML -ScanAllCLSIDs -OutputPath $path 
    }
    "0" { 
        Write-Host "Exiting..." -ForegroundColor Gray
        exit 
    }
    default { 
        Write-Host "[-] Invalid choice" -ForegroundColor Red 
    }
}
