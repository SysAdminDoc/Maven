# Define the base URL
$baseUrl = "https://medicatechusa.com/wp-content/uploads/voyance/"

# Get the HTML content of the directory listing
$htmlContent = Invoke-WebRequest -Uri $baseUrl

# Use a regular expression to extract the download link with the wildcard
$pattern = "Voyance(\d+\.\d+\.\d+)\.exe"
$matches = [regex]::Matches($htmlContent.Content, $pattern)

# Find the latest version number
$latestVersion = $null
foreach ($match in $matches) {
    $version = $match.Groups[1].Value
    if ($latestVersion -eq $null -or [Version]$version -gt [Version]$latestVersion) {
        $latestVersion = $version
    }
}

# Construct the download URL for the latest version
$downloadUrl = $baseUrl + "Voyance$latestVersion.exe"

# Define the local path to save the downloaded file
$localFilePath = "C:\MTU\Voyance$latestVersion.exe"

# Download the file
Invoke-WebRequest -Uri $downloadUrl -OutFile $localFilePath

Write-Host "Downloaded the latest version of Voyance ($latestVersion) to $localFilePath."
