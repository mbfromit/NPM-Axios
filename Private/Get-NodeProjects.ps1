function Get-NodeProjects {
    [CmdletBinding()]
    param(
        [string[]]$Path = @('C:\Users', 'C:\Dev', 'C:\Projects')
    )
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($rootPath in $Path) {
        if (-not (Test-Path $rootPath)) { Write-Warning "Path not found, skipping: $rootPath"; continue }
        try {
            Get-ChildItem -Path $rootPath -Recurse -Filter 'package.json' -ErrorAction SilentlyContinue -Force |
            Where-Object { $_.FullName -notmatch [regex]::Escape([IO.Path]::DirectorySeparatorChar + 'node_modules' + [IO.Path]::DirectorySeparatorChar) -and $_.FullName -notmatch '/node_modules/' } |
            ForEach-Object { $results.Add([PSCustomObject]@{ ProjectPath = $_.DirectoryName; PackageJsonPath = $_.FullName }) }
        } catch { Write-Warning "Error scanning ${rootPath}: $_" }
    }
    return @($results)
}
