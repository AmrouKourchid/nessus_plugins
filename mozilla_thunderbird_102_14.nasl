#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-32.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(179227);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/07");

  script_cve_id(
    "CVE-2023-4045",
    "CVE-2023-4046",
    "CVE-2023-4047",
    "CVE-2023-4048",
    "CVE-2023-4049",
    "CVE-2023-4050",
    "CVE-2023-4054",
    "CVE-2023-4055",
    "CVE-2023-4056"
  );

  script_name(english:"Mozilla Thunderbird < 102.14");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 102.14. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2023-32 advisory.

  - Offscreen Canvas did not properly track cross-origin tainting, which could have been used to access image
    data from another site in violation of same-origin policy. (CVE-2023-4045)

  - In some circumstances, a stale value could have been used for a global variable in WASM JIT analysis. This
    resulted in incorrect compilation and a potentially exploitable crash in the content process.
    (CVE-2023-4046)

  - A bug in popup notifications delay calculation could have made it possible for an attacker to trick a user
    into granting permissions. (CVE-2023-4047)

  - An out-of-bounds read could have led to an exploitable crash when parsing HTML with DOMParser in low
    memory situations. (CVE-2023-4048)

  - Race conditions in reference counting code were found through code inspection. These could have resulted
    in potentially exploitable use-after-free vulnerabilities. (CVE-2023-4049)

  - In some cases, an untrusted input stream was copied to a stack buffer without checking its size. This
    resulted in a potentially exploitable crash which could have led to a sandbox escape. (CVE-2023-4050)

  - When opening appref-ms files, Firefox did not warn the user that these files may contain malicious code.
    This bug only affects Firefox on Windows. Other operating systems are unaffected. (CVE-2023-4054)

  - When the number of cookies per domain was exceeded in <code>document.cookie</code>, the actual cookie jar
    sent to the host was no longer consistent with expected cookie jar state. This could have caused requests
    to be sent with some cookies missing. (CVE-2023-4055)

  - Memory safety bugs present in Firefox 115, Firefox ESR 115.0, Firefox ESR 102.13, Thunderbird 115.0, and
    Thunderbird 102.13. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. (CVE-2023-4056)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 102.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4056");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'102.14', severity:SECURITY_HOLE);
