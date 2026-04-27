# Debugger Detector

Debug detection is a technique that helps your app (Anti-Cheat) recognize when someone is trying to analyze or manipulate it using a debugger.

There are different methods to debug a program. We're gonna cover some of them in this studdy.
- Dynamic Analysis Tools: Tools commonly used by cheaters to debug a program (e.g. CheatEngine, x64dbg, IDA Pro)
- Hardware Breakpoints: Unlike software breakpoints, these utilize physical processor resources.
- Kernel debuggers (WinDbg): Allow you to pause the entire operating system. They usually require two computers connected via cable or network.

[What is Debug Detection?](https://digital.ai/debug-detection/) <br>
[Understanding Debugger Detection on Windows: Three Practical Techniques](https://medium.com/@andrenetwork.sec/understanding-debugger-detection-on-windows-three-practical-techniques-9f7fa9699118) <br>
[Debugger Detection Techniques: The Summary of a Summary](https://aams-eam.pages.dev/posts/debugger-detection-techniques_the-summary-of-a-summary/) <br>
[Anti Debug: TLS Callback](https://unprotect.it/technique/tls-callback/) <br>
[UltimateAntiCheat DebuggerDetections](https://github.com/AlSch092/UltimateAntiCheat/blob/main/AntiDebug/DebuggerDetections.cpp)

# TLS Callback

- TLS Callbacks are functions executed by the OS before the program’s entry point (Main). This is crucial for debugger detection because many entry-level reverse engineers expect execution to start at Main, and most debuggers are configured to break there by default. By embedding anti-debugging logic within a TLS Callback, a program can detect a debugger and terminate the process before the analyst even sees the first line of the Main function.

[TLS Callback](https://unprotect.it/technique/tls-callback/)
[TLS_Examples](https://github.com/kevinalmansa/TLS_Examples)
[TLS Callbacks to bypass debuggers](https://medium.com/@andreabocchetti88/tls-callbacks-to-bypass-debuggers-60409195ed76)
