
out\windows\bin\next.exe test_tamper.c /MD /O2 /Zi -Wm,-nopresets,-anti-tamper,-anti-tamper-frequency=0,-anti-tamper-min-guards=1,-anti-tamper-no-integrity,-anti-tamper-debug,-reopt,-anti-tamper-exit /Fetest_tamper_debug.exe

out\windows\bin\next.exe test_tamper.c /MD /O2 /Zi -Wm,-nopresets,-anti-tamper,-anti-tamper-frequency=0,-anti-tamper-min-guards=1,-anti-tamper-no-integrity,-reopt,-anti-tamper-exit

editbin /DYNAMICBASE:NO test_tamper.exe
editbin /DYNAMICBASE:NO test_tamper_debug.exe