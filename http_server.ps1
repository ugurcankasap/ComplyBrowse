# Simple HTTP Server for serving files
# Usage: powershell -File http_server.ps1 -Port 8888 -Path "C:\path"

param(
    [int]$Port = 8888,
    [string]$Path = (Get-Location).Path
)

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")

try {
    $listener.Start()
    Write-Host "HTTP Server started on http://localhost:$Port/" -ForegroundColor Green
    Write-Host "Serving files from: $Path" -ForegroundColor Green
    
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $requestPath = $request.Url.LocalPath.TrimStart('/')
        $filePath = Join-Path $Path $requestPath
        
        Write-Host "Request: $requestPath -> $filePath" -ForegroundColor Cyan
        
        if ([System.IO.File]::Exists($filePath)) {
            Write-Host "[OK] File found" -ForegroundColor Green
            $fileContent = [System.IO.File]::ReadAllBytes($filePath)
            $response.ContentLength64 = $fileContent.Length
            
            # Set content type
            $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
            $contentType = switch ($ext) {
                ".html" { "text/html" }
                ".json" { "application/json" }
                ".js" { "application/javascript" }
                ".css" { "text/css" }
                ".bat" { "text/plain" }
                ".ps1" { "text/plain" }
                default { "application/octet-stream" }
            }
            
            $response.ContentType = $contentType
            $response.OutputStream.Write($fileContent, 0, $fileContent.Length)
        } else {
            Write-Host "[ERROR] File NOT found: $filePath" -ForegroundColor Red
            $response.StatusCode = 404
            $response.StatusDescription = "Not Found"
        }
        
        $response.OutputStream.Close()
    }
} catch {
    Write-Host "Server error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    $listener.Stop()
    $listener.Close()
}
