/*
 * test.yar - a minimal rule set for testing the YARA integration itself.
 *
 * This deliberately does NOT duplicate the SHA-256 EICAR signature
 * already in av/main.c - the point is to prove the YARA path works
 * independently (string/pattern matching, not hash lookup). Real
 * malware rule sets go in this directory too (e.g. pulled from
 * community rule repositories) once you're testing against actual
 * samples rather than just the plumbing.
 */

rule EICAR_Test_String
{
    meta:
        description = "Detects the standard EICAR antivirus test string"
        author = "kernel-av project"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}

rule Suspicious_Shell_Reverse_Shell_String
{
    meta:
        description = "Flags a common /bin/sh -i reverse shell pattern - test rule, not a real detector"
        author = "kernel-av project"

    strings:
        $pattern = "/bin/sh -i"

    condition:
        $pattern
}
