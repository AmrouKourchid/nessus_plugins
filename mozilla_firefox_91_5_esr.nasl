#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-02.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156603);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/21");

  script_cve_id(
    "CVE-2021-4140",
    "CVE-2022-22737",
    "CVE-2022-22738",
    "CVE-2022-22739",
    "CVE-2022-22740",
    "CVE-2022-22741",
    "CVE-2022-22742",
    "CVE-2022-22743",
    "CVE-2022-22744",
    "CVE-2022-22745",
    "CVE-2022-22746",
    "CVE-2022-22747",
    "CVE-2022-22748",
    "CVE-2022-22751"
  );
  script_xref(name:"IAVA", value:"2022-A-0017-S");

  script_name(english:"Mozilla Firefox ESR < 91.5");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 91.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2022-02 advisory.

  - A race condition could have allowed bypassing the fullscreen notification which could have lead to a
    fullscreen window spoof being unnoticed. This bug only affects Thunderbird for Windows. Other operating
    systems are unaffected. (CVE-2022-22746)

  - When navigating from inside an iframe while requesting fullscreen access, an attacker-controlled tab could
    have made the browser unable to leave fullscreen mode. (CVE-2022-22743)

  - When inserting text while in edit mode, some characters might have lead to out-of-bounds memory access
    causing a potentially exploitable crash. (CVE-2022-22742)

  - When resizing a popup while requesting fullscreen access, the popup would have become unable to leave
    fullscreen mode. (CVE-2022-22741)

  - Certain network request objects were freed too early when releasing a network request handle. This could
    have lead to a use-after-free causing a potentially exploitable crash. (CVE-2022-22740)

  - Applying a CSS filter effect could have accessed out of bounds memory. This could have lead to a heap-
    buffer-overflow causing a potentially exploitable crash. (CVE-2022-22738)

  - Constructing audio sinks could have lead to a race condition when playing audio files and closing windows.
    This could have lead to a use-after-free causing a potentially exploitable crash. (CVE-2022-22737)

  - It was possible to construct specific XSLT markup that would be able to bypass an iframe sandbox.
    (CVE-2021-4140)

  - Malicious websites could have confused Thunderbird into showing the wrong origin when asking to launch a
    program and handling an external URL protocol. (CVE-2022-22748)

  - Securitypolicyviolation events could have leaked cross-origin information for frame-ancestors violations
    (CVE-2022-22745)

  - The constructed curl command from the Copy as curl feature in DevTools was not properly escaped for
    PowerShell.  This could have lead to command injection if pasted into a Powershell prompt. This bug only
    affects Firefox for Windows. Other operating systems are unaffected. (CVE-2022-22744)

  - After accepting an untrusted certificate, handling an empty pkcs7 sequence as part of the certificate data
    could have lead to a crash. This crash is believed to be unexploitable. (CVE-2022-22747)

  - Malicious websites could have tricked users into accepting launching a program to handle an external URL
    protocol. (CVE-2022-22739)

  - Mozilla developers Calixte Denizet, Kershaw Chang, Christian Holler, Jason Kratzer, Gabriele Svelto, Tyson
    Smith, Simon Giesecke, and Steve Fink reported memory safety bugs present in Firefox 95 and Firefox ESR
    91.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. (CVE-2022-22751)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-02/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 91.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22751");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4140");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'91.5', min:'91.0.0', severity:SECURITY_HOLE);
