@echo off
rem 4q — short alias for 4n6query
rem %~dp0 expands to the directory containing this batch file (with trailing \).
rem The outer quotes around the binary path handle spaces in the install dir.
"%~dp04n6query.exe" %*
