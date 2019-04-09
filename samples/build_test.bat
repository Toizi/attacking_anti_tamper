set input_name=%1

out\windows\bin\next.exe %input_name%.cpp /MD /O2 /Zi -Wm,-seed=2,-nopresets,-anti-tamper,-anti-tamper-frequency=0,-anti-tamper-min-guards=1,-anti-tamper-no-integrity,-anti-tamper-debug,-reopt,-anti-tamper-exit,-v /Fe%input_name%_debug.exe

out\windows\bin\next.exe %input_name%.cpp /MD /O2 /Zi -Wm,-seed=2,-nopresets,-anti-tamper,-anti-tamper-frequency=0,-anti-tamper-min-guards=1,-anti-tamper-no-integrity,-reopt,-anti-tamper-exit,-v

editbin /DYNAMICBASE:NO %input_name%.exe
editbin /DYNAMICBASE:NO %input_name%_debug.exe