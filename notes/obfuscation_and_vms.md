## Revisit Later

### UltimateAntiCheat VM bytecode execution (AntiCheat.cpp constructor)
- Custom VM that interprets obfuscated bytecode
- Uses pointer-to-member dance to get method address as integer
- Uses OBFUSCATE macro to XOR values at compile time
- Purpose: hide anti-cheat logic from static analysis

### Related concept — VMProtect
VMProtect is a code virtualization tool that converts normal CPU instructions
into a custom virtual bytecode. This bytecode is then executed by a small 
virtual machine embedded inside the program.

In anti-cheats, VMProtect is used to heavily obfuscate critical detection
functions. It makes it extremely difficult and time-consuming for cheat
developers to understand, reverse engineer, or bypass the anti-cheat.

**Connection:** UltimateAntiCheat's custom VM is a homemade, simplified
version of what VMProtect does commercially. Same idea — execute bytecode
instead of native instructions, so attackers can't just disassemble the
binary to understand the protection logic.

Vanguard (Valorant) uses VMProtect extensively on its kernel driver and
detection routines — one of the reasons it's considered one of the hardest
anti-cheats to reverse.
