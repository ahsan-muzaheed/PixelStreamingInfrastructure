# Copyright 1998-2018 Epic Games, Inc. All Rights Reserved.

$PublicIp = Invoke-RestMethod http://ipinfo.io/json | Select -exp ip
#$PublicIp = "127.0.0.1"

Write-Output "Public IP: $PublicIp"


$ProcessExe1 = "C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\UnrealEditor.exe"

$ProcessExe2 = "C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe -project C:\0.ps\psTest_5_1\psTest_5_1.uproject -RenderOffscreen -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingStartOnLaunch=true -PixelStreamingURL=ws://127.0.0.1:8888"

$ProcessExe_worked = "C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log -RenderOffscreen -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingStartOnLaunch=true -PixelStreamingURL="ws://127.0.0.1:8888"
$ProcessExe = "C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log -RenderOffscreen -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingStartOnLaunch=true -PixelStreamingURL="ws://127.0.0.1:8888"



$Arguments11 = @("-EditorPixelStreamingStartOnLaunch=true","-EditorPixelStreamingRes=1920x1080", "--serverPublicIp=$PublicIp")
$Arguments = @("-dfdgdg=0")
# Add arguments passed to script to Arguments for executable
$Arguments += $args

Write-Output "Running: $ProcessExe $Arguments"
Start-Process -FilePath $ProcessExe -ArgumentList $Arguments -Wait -NoNewWindow
