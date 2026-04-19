# anticheat-research

I've been working with malware analysis and reverse engineering for a while now,
and recently started diving deeper into how anti-cheat
systems work under the hood.

This repo documents that journey. Notes on techniques I'm studying, and
implementations I'm building as I understand them well enough to write code.

The starting point was practical: I previously built external cheats for games
(Borderlands 3, Assault Cube) —> memory R/W, ESP overlays, aimbots. That gave me
a solid understanding of the attack surface. Now I'm flipping sides.

---

## Structure

\`\`\`
anticheat-research/
├── notes/    ← concepts I'm studying, written in my own words
└── src/      ← implementations as I learn each technique
\`\`\`

---

## Topics being covered

**Detection techniques (usermode)**
- IAT validation — detecting hooks on imported functions
- Debugger detection — IsDebuggerPresent, hardware breakpoints, TLS callbacks
- Thread integrity — spotting unknown threads inside the process
- Module scanning — flagging unsigned or unexpected DLLs
- Inline hook detection — checking for JMP patches at function preambles
- Parent process validation — ensuring the game was launched legitimately

**System-level concepts**
- Ring 0 vs Ring 3 — why kernel-level anti-cheat exists
- Driver Signature Enforcement (DSE)
- Secure Boot enforcement
- Hypervisor detection

**String obfuscation**
- Compile-time encryption to hide sensitive strings from static analysis

---

## References I'm using

- [UltimateAntiCheat](https://github.com/AlSch092/UltimateAntiCheat) — open source AC reference
- [GuidedHacking](https://guidedhacking.com) — game hacking fundamentals

---

## Background

- Software Engineer at TopSaúde - Systems development (Brazilian healthcare sector company)
- Malware analyst at Mosyle (daily RE of macOS threats, using Binary Ninja)
- CompTIA Security+, PenTest+, Google Cybersec. Certificate
- Game security research: [Tox1cP4nd4](https://github.com/Tox1cP4nd4)
