## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2022-25.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(162605);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/19");

  script_cve_id(
    "CVE-2022-2200",
    "CVE-2022-31744",
    "CVE-2022-34468",
    "CVE-2022-34470",
    "CVE-2022-34472",
    "CVE-2022-34478",
    "CVE-2022-34479",
    "CVE-2022-34481",
    "CVE-2022-34484"
  );
  script_xref(name:"IAVA", value:"2022-A-0226-S");
  script_xref(name:"IAVA", value:"2022-A-0256-S");

  script_name(english:"Mozilla Firefox ESR < 91.11");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote macOS or Mac OS X host is prior to 91.11. It is, therefore, affected
by multiple vulnerabilities as referenced in the mfsa2022-25 advisory.

  - A malicious website that could create a popup could have resized the popup to overlay the address bar with
    its own content, resulting in potential user confusion or spoofing attacks.   This bug only affects
    Firefox for Linux. Other operating systems are unaffected. (CVE-2022-34479)

  - Navigations between XML documents may have led to a use-after-free and potentially exploitable crash.
    (CVE-2022-34470)

  - An iframe that was not permitted to run scripts could do so if the user clicked on a
    <code>javascript:</code> link. (CVE-2022-34468)

  - In the <code>nsTArrayImpl::ReplaceElementsAt()</code> function, an integer overflow could have occurred
    when the number of elements to replace was too large for the container. (CVE-2022-34481)

  - An attacker could have injected CSS into stylesheets accessible via internal URIs, such as resource:, and
    in doing so bypass a page's Content Security Policy. (CVE-2022-31744)

  - If there was a PAC URL set and the server that hosts the PAC was not reachable, OCSP requests would have
    been blocked, resulting in incorrect error pages being shown. (CVE-2022-34472)

  - The <code>ms-msdt</code>, <code>search</code>, and <code>search-ms</code> protocols deliver content to
    Microsoft applications, bypassing the browser, when a user accepts a prompt. These applications have had
    known vulnerabilities, exploited in the wild (although we know of none exploited through Firefox), so in
    this release Firefox has blocked these protocols from prompting the user to open them. This bug only
    affects Firefox on Windows. Other operating systems are unaffected. (CVE-2022-34478)

  - If an object prototype was corrupted by an attacker, they would have been able to set undesired attributes
    on a JavaScript object, leading to privileged code execution. (CVE-2022-2200)

  - The Mozilla Fuzzing Team reported potential vulnerabilities present in Firefox 101 and Firefox ESR 91.10.
    Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of
    these could have been exploited to run arbitrary code. (CVE-2022-34484)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-25/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 91.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34484");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34470");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var kb_base = 'MacOSX/Firefox';
get_kb_item_or_exit(kb_base+'/Installed');

var version = get_kb_item_or_exit(kb_base+'/Version', exit_code:1);
var path = get_kb_item_or_exit(kb_base+'/Path', exit_code:1);

var is_esr = get_kb_item(kb_base+'/is_esr');
if (isnull(is_esr)) audit(AUDIT_NOT_INST, 'Mozilla Firefox ESR');

mozilla_check_version(version:version, path:path, product:'firefox', esr:TRUE, fix:'91.11', min:'91.0.0', severity:SECURITY_HOLE);
