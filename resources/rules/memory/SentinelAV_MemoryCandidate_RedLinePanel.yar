// For feedback or questions contact us at: github@eset.com
// https://github.com/eset/malware-ioc/
//
// These YARA rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2024, ESET
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



// SentinelAV adaptation: memory candidate only; file gate removed. Never an automatic response verdict.
rule SentinelAV_MemoryCandidate_RedLinePanel
{
    meta:
        description = "Matches view headers in Redline Panel"
        author = "ESET Research"
        date = "2022-10-11"
        last_modified = "2024-11-12"
        hash = "A154DFAEDC237C047F419EB6884DAB1EF4E2A17D"
        reference = "https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = 2
    strings:
        $ = "RedLine | Log In"
        $ = "RedLine | Autofilles Viewer"
        $ = "RedLine | Choose Browser"
        $ = "RedLine | Cookie Viewer"
        $ = "RedLine | Credit Card Viewer"
        $ = "RedLine | Files Viewer"
        $ = "RedLine | Log saver"
        $ = "RedLine | System Info Viewer"
    condition:
        6 of them
}


