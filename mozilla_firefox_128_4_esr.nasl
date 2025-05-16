#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-56.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(209868);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id(
    "CVE-2024-10458",
    "CVE-2024-10459",
    "CVE-2024-10460",
    "CVE-2024-10461",
    "CVE-2024-10462",
    "CVE-2024-10463",
    "CVE-2024-10464",
    "CVE-2024-10465",
    "CVE-2024-10466",
    "CVE-2024-10467"
  );
  script_xref(name:"IAVA", value:"2024-A-0695-S");

  script_name(english:"Mozilla Firefox ESR < 128.4");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 128.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2024-56 advisory.

  - A permission leak could have occurred from a trusted site to an untrusted site via <code>embed</code> or
    <code>object</code> elements. (CVE-2024-10458)

  - An attacker could have caused a use-after-free when accessibility was enabled, leading to a potentially
    exploitable crash. (CVE-2024-10459)

  - The origin of an external protocol handler prompt could have been obscured using a data: URL within an
    <code>iframe</code>. (CVE-2024-10460)

  - In multipart/x-mixed-replace responses, <code>Content-Disposition: attachment</code> in the response
    header was not respected and did not force a download, which could allow XSS attacks. (CVE-2024-10461)

  - Truncation of a long URL could have allowed origin spoofing in a permission prompt. (CVE-2024-10462)

  - Video frames could have been leaked between origins in some situations. (CVE-2024-10463)

  - Repeated writes to history interface attributes could have been used to cause a Denial of Service
    condition in the browser. This was addressed by introducing rate-limiting to this API. (CVE-2024-10464)

  - A clipboard paste button could persist across tabs which allowed a spoofing attack. (CVE-2024-10465)

  - By sending a specially crafted push message, a remote server could have hung the parent process, causing
    the browser to become unresponsive. (CVE-2024-10466)

  - Memory safety bugs present in Firefox 131, Firefox ESR 128.3, and Thunderbird 128.3. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-10467)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-56/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 128.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10467");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'128.4', min:'128.0.0', severity:SECURITY_HOLE);
