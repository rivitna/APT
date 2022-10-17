/*
RCSession
*/

rule RCSession_Payload
{
    meta:
        author = "rivitna"
        family = "RCSession"
        description = "RCSession payload"
        severity = 10
        score = 100

    strings:
        $a0 = ".?AVCNet@@" ascii
        $a1 = ".?AVCNetHttp@@" ascii
        $a2 = ".?AVCNetPipe@@" ascii
        $a3 = ".?AVCNetTcp@@" ascii
        $a4 = ".?AVCNetUdp@@" ascii
        $a5 = ".?AVCFileManager@@" ascii
        $a6 = ".?AVCPlugin@@" ascii
        $a7 = ".?AVCKeyLog@@" ascii
        $a8 = ".?AVCPortMap@@" ascii
        $a9 = ".?AVCScreen@@" ascii
        $a10 = ".?AVCShell@@" ascii
        $a11 = ".?AVCTelnet@@" ascii
        $a12 = "\x00Software\\Clients\\Profile" wide
        $a13 = "\x00XBEE\x00" wide

        $x0 = { 83 E8 00 74 19 48 74 0F 48 74 05 6B C9 09 EB 15 8B C1
                C1 E8 02 EB 03 8D 04 09 2B C8 EB 07 8B C1 C1 E8 04 03 C8 }

    condition:
        ((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) and
        (
            (5 of ($a*)) or
            (1 of ($x*))
        )
}
