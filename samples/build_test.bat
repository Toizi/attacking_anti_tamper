
out\windows\bin\next.exe test_tamper.c /MD /O2 /Zi -Wm,-nopresets,-anti-tamper,-anti-tamper-frequency=0,-anti-tamper-min-guards=1,-anti-tamper-no-integrity,-anti-tamper-debug /Fetest_tamper_debug.exe

out\windows\bin\next.exe test_tamper.c /MD /O2 /Zi -Wm,-nopresets,-anti-tamper,-anti-tamper-frequency=0,-anti-tamper-min-guards=1,-anti-tamper-no-integrity
