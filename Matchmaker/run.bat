:: Copyright Epic Games, Inc. All Rights Reserved.
@echo off

pushd %~dp0

::call setup.bat

title Matchmaker

::Run node server
::pm2 start matchmaker.js %*
node matchmaker.js %*

popd
pause
