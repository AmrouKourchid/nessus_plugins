#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-20.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(193588);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id(
    "CVE-2024-2609",
    "CVE-2024-3302",
    "CVE-2024-3852",
    "CVE-2024-3854",
    "CVE-2024-3857",
    "CVE-2024-3859",
    "CVE-2024-3861",
    "CVE-2024-3863",
    "CVE-2024-3864"
  );
  script_xref(name:"IAVA", value:"2024-A-0174-S");
  script_xref(name:"IAVA", value:"2024-A-0257-S");

  script_name(english:"Mozilla Thunderbird < 115.10");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 115.10. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2024-20 advisory.

  - GetBoundName could return the wrong version of an object when JIT optimizations were applied.
    (CVE-2024-3852)

  - In some code patterns the JIT incorrectly optimized switch statements and generated code with out-of-
    bounds-reads. (CVE-2024-3854)

  - The JIT created incorrect code for arguments in certain cases. This led to potential use-after-free
    crashes during garbage collection. (CVE-2024-3857)

  - The permission prompt input delay could expire while the window is not in focus. This makes it vulnerable
    to clickjacking by malicious websites. (CVE-2024-2609)

  - On 32-bit versions there were integer-overflows that led to an out-of-bounds-read that potentially could
    be triggered by a malformed OpenType font. (CVE-2024-3859)

  - If an AlignedBuffer were assigned to itself, the subsequent self-move could result in an incorrect
    reference count and later use-after-free. (CVE-2024-3861)

  - The executable file warning was not presented when downloading .xrm-ms files.   Note: This issue only
    affected Windows operating systems. Other operating systems are unaffected. (CVE-2024-3863)

  - There was no limit to the number of HTTP/2 CONTINUATION frames that would be processed. A server could
    abuse this to create an Out of Memory condition in the browser. (CVE-2024-3302)

  - Memory safety bug present in Firefox 124, Firefox ESR 115.9, and Thunderbird 115.9. This bug showed
    evidence of memory corruption and we presume that with enough effort this could have been exploited to run
    arbitrary code. (CVE-2024-3864)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-20/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 115.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3863");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'115.10', severity:SECURITY_HOLE);
