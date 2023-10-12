// This file contain Yara rule for opcodes which target CS version 4.9.1 and prior.
// This yara target the Socks and Remote Connection functionality which cannot
// be modified by an operator. These can only be modified by Fortra as it needs
// changes to the source code. This detection was written to target leaked  CS 4.9
// versions, but has been tested backwards till v4.5.
// This yara wont hit beacon.exe, it was written for the shellcode
// This yara was specially crafted for the core (in-memory scans) which cannot be
// avoided in way by an operator, making the malleability, UDRL or IAT hooking useless

rule cs45_49_core {
    meta:
        version = "0.1"
        author = "@ninjaparanoid"
        description = "Hunts for opcodes used in Cobaltstrike 4.9.1 and earlier"
        arch_context = "x64"
    strings:
        $socks = { 49 8D 55 02 48 8D 4C 24 30 44 0F B7 F8 B8 FF 03 00 00 }
        $core = { 49 B9 01 01 01 01 01 01 01 01 49 0F AF D1 49 83 F8 40 }
    condition:
        $socks
        or
        $core
}
