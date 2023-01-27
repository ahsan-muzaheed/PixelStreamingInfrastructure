
:: Copyright 1998-2019 Epic Games, Inc. All Rights Reserved.
@echo off

pushd %~dp0

::call setup.bat

title ExeLuncher(SocketIO client)

::Run node server
::If running with frontend web server and accessing outside of localhost pass in --publicIp=<ip_of_machine>
::node ExeLuncher %*
::Powershell.exe -executionpolicy unrestricted -File ue_editor_ps.ps1 

::"C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log -RenderOffscreen -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingUseRemoteSignallingServer=true -EditorPixelStreamingStartOnLaunch=true -PixelStreamingURL="wss://127.0.0.1:8888" 

::"C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log -RenderOffscreen -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingUseRemoteSignallingServer=true -EditorPixelStreamingStartOnLaunch=true -PixelStreamingURL="wss://ue5ps.eaglepixelstreaming.com:8888"

::"C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingUseRemoteSignallingServer=true -EditorPixelStreamingStartOnLaunch=true -PixelStreamingURL=ws://ue5ps.eaglepixelstreaming.com:8888

::"C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingUseRemoteSignallingServer=true -EditorPixelStreamingStartOnLaunch=true -PixelStreamingURL=ws://99.60.91.141:8888

::"C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingStartOnLaunch=false 


::"C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingUseRemoteSignallingServer=true -EditorPixelStreamingStartOnLaunch=false  -PixelStreamingURL=ws://99.60.91.141:8888
::"C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project "C:\0.ps\VISTNext\VISTNext.uproject" -log -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingUseRemoteSignallingServer=true -EditorPixelStreamingStartOnLaunch=false  -PixelStreamingURL=ws://99.60.91.141:8888


"C:\Program Files\Epic Games\UE_5.1\Engine\Binaries\Win64\\UnrealEditor-Cmd.exe" -project  "C:\0.ps\psTest_5_1\psTest_5_1.uproject" -log  -RenderOffscreen -EditorPixelStreamingRes=1920x1080 -EditorPixelStreamingStartOnLaunch=true -PixelStreamingURL=ws://192.168.0.10:8888



popd 
pause
::exit



