rule ransomware_wannahusky {

    meta:
        author      = "Mars"
        description = "Rule to detect Ransomware.Wannahusky"
        hash        = "3D35CEBCF40705C23124FDC4656A7F400A316B8E96F1F9E0C187E82A9D17DCA3"
        created     = "2022-04-05"

    strings:
        $s1 = "WANNAHUSKY.png" ascii
        $s2 = "cosmo.WANNAHUSKY" ascii
        $s3 = "ps1.ps1" ascii
        $s4 = "nim" ascii

    condition:
        uint16(0) == 0x5A4D and any of them
}