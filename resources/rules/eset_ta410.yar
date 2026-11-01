// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2022, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

import "pe"


rule apt_Windows_TA410_Tendyron_dropper
{
    meta:
        description = "TA410 Tendyron Dropper"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-12-09"
    strings:
        $s1 = "Global\\{F473B3BE-08EE-4710-A727-9E248F804F4A}" wide
        $s2 = "Global\\8D32CCB321B2" wide
        $s3 = "Global\\E4FE94F75490" wide
        $s4 = "Program Files (x86)\\Internet Explorer\\iexplore.exe" wide
        $s5 = "\\RPC Control\\OLE" wide
        $s6 = "ALPC Port" wide
    condition:
        int16(0) == 0x5A4D and 4 of them
}


rule apt_Windows_TA410_X4_hash_values
{
    meta:
        description = "Matches X4 hash function found in TA410 X4"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2020-10-09"
    strings:
        $s1 = {D1 10 76 C2 B6 03}
        $s2 = {71 3E A8 0D}
        $s3 = {DC 78 94 0E}
        $s4 = {40 0D E7 D6 06}
        $s5 = {83 BB FD E8 06}
        $s6 = {92 9D 9B FF EC 03}
        $s7 = {DD 0E FC FA F5 03}
        $s8 = {15 60 1E FB F5 03}
    condition:
        uint16(0) == 0x5a4d and 4 of them

}

