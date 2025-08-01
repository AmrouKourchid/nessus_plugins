## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-14.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(148773);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/03");

  script_cve_id(
    "CVE-2021-23961",
    "CVE-2021-23994",
    "CVE-2021-23995",
    "CVE-2021-23998",
    "CVE-2021-23999",
    "CVE-2021-24002",
    "CVE-2021-29945",
    "CVE-2021-29946",
    "CVE-2021-29948"
  );

  script_name(english:"Mozilla Thunderbird < 78.10");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 78.10. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2021-14 advisory.

  - A WebGL framebuffer was not initialized early enough, resulting in memory corruption and an out of bound
    write. (CVE-2021-23994)

  - When Responsive Design Mode was enabled, it used references to objects that were previously freed. We
    presume that with enough effort this could have been exploited to run arbitrary code. (CVE-2021-23995)

  - Through complicated navigations with new windows, an HTTP page could have inherited a secure lock icon
    from an HTTPS page. (CVE-2021-23998)

  - Further techniques that built on the slipstream research combined with a malicious webpage could have
    exposed both an internal network's hosts as well as services running on the user's local machine.
    (CVE-2021-23961)

  - If a Blob URL was loaded through some unusual user interaction, it could have been loaded by the System
    Principal and granted additional privileges that should not be granted to web content. (CVE-2021-23999)

  - When a user clicked on an FTP URL containing encoded newline characters (%0A and %0D), the newlines would
    have been interpreted as such and allowed arbitrary commands to be sent to the FTP server.
    (CVE-2021-24002)

  - The WebAssembly JIT could miscalculate the size of a return type, which could lead to a null read and
    result in a crash. Note: This issue only affected x86-32 platforms. Other platforms are unaffected.
    (CVE-2021-29945)

  - Ports that were written as an integer overflow above the bounds of a 16-bit integer could have bypassed
    port blocking restrictions when used in the Alt-Svc header. (CVE-2021-29946)

  - Signatures are written to disk before and read during verification, which might be subject to a race
    condition when a malicious local process or user is replacing the file. (CVE-2021-29948)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-14/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 78.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'78.10', severity:SECURITY_WARNING);
