function Get-NodeProjects {
    [CmdletBinding()]
    param(
        [string[]]$Path           = @('C:\Users', 'C:\Dev', 'C:\Projects'),
        [string[]]$ExcludePattern = @('[/\\][Tt]ests[/\\][Ff]ixtures[/\\]', '[/\\]tests[/\\]fixtures[/\\]')
    )
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($rootPath in $Path) {
        if (-not (Test-Path $rootPath)) { Write-Warning "Path not found, skipping: $rootPath"; continue }
        try {
            Get-ChildItem -Path $rootPath -Recurse -Filter 'package.json' -ErrorAction SilentlyContinue -Force |
            Where-Object {
                $fn = $_.FullName
                if ($fn -match '[/\\]node_modules[/\\]') { return $false }
                if ($fn -match '[/\\]\.(git|svn|hg|vs|idea|vscode)[/\\]') { return $false }
                if ($fn -match '[/\\](bin|obj|dist|build|out|coverage|__pycache__)[/\\]') { return $false }
                if ($ExcludePattern) {
                    foreach ($pat in $ExcludePattern) { if ($fn -match $pat) { return $false } }
                }
                return $true
            } |
            ForEach-Object { $results.Add([PSCustomObject]@{ ProjectPath = $_.DirectoryName; PackageJsonPath = $_.FullName }) }
        } catch { Write-Warning "Error scanning ${rootPath}: $_" }
    }
    return @($results)
}
