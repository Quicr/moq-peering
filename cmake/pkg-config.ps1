# Picotls requires pkg-config before it looks for optional libraries such as brotli.
# CMake runs this through powershell.exe. A .cmd stub fails: cmd.exe treats the
# forward-slash path D:/a/... as a switch and never executes the file.
$first = ""
if ($args.Count -gt 0) {
    $first = [string]$args[0]
}

if ($first -eq "--version") {
    [Console]::Out.WriteLine("0.29.2")
    exit 0
}

if ($first -eq "--help") {
    [Console]::Out.WriteLine("pkg-config stub for the Windows build")
    exit 0
}

exit 1
