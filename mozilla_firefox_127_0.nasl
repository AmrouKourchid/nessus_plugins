#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2024-25.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(200315);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2024-5687",
    "CVE-2024-5688",
    "CVE-2024-5689",
    "CVE-2024-5690",
    "CVE-2024-5691",
    "CVE-2024-5692",
    "CVE-2024-5693",
    "CVE-2024-5694",
    "CVE-2024-5695",
    "CVE-2024-5696",
    "CVE-2024-5697",
    "CVE-2024-5698",
    "CVE-2024-5699",
    "CVE-2024-5700",
    "CVE-2024-5701"
  );
  script_xref(name:"IAVA", value:"2024-A-0335-S");

  script_name(english:"Mozilla Firefox < 127.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior to 127.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2024-25 advisory.

  - If a specific sequence of actions is performed when opening a new tab, the triggering principal associated
    with the new tab may have been incorrect. The triggering principal is used to calculate many values,
    including the <code>Referer</code> and <code>Sec-</code> headers, meaning there is the potential for
    incorrect security checks within the browser in addition to incorrect or misleading information sent to
    remote websites. This bug only affects Firefox for Android. Other versions of Firefox are unaffected.
    (CVE-2024-5687)

  - If a garbage collection was triggered at the right time, a use-after-free could have occurred during
    object transplant. (CVE-2024-5688)

  - In addition to detecting when a user was taking a screenshot (XXX), a website was able to overlay the 'My
    Shots' button that appeared, and direct the user to a replica Firefox Screenshots page that could be used
    for phishing. (CVE-2024-5689)

  - By monitoring the time certain operations take, an attacker could have guessed which external protocol
    handlers were functional on a user's system. (CVE-2024-5690)

  - By tricking the browser with a <code>X-Frame-Options</code> header, a sandboxed iframe could have
    presented a button that, if clicked by a user, would bypass restrictions to open a new window.
    (CVE-2024-5691)

  - On Windows, when using the 'Save As' functionality, an attacker could have tricked the browser into saving
    the file with a disallowed extension such as <code>.url</code> by including an invalid character in the
    extension. Note: This issue only affected Windows operating systems. Other operating systems are
    unaffected. (CVE-2024-5692)

  - Offscreen Canvas did not properly track cross-origin tainting, which could be used to access image data
    from another site in violation of same-origin policy. (CVE-2024-5693)

  - An attacker could have caused a use-after-free in the JavaScript engine to read memory in the JavaScript
    string section of the heap. (CVE-2024-5694)

  - If an out-of-memory condition occurs at a specific point using allocations in the probabilistic heap
    checker, an assertion could have been triggered, and in rarer situations, memory corruption could have
    occurred. (CVE-2024-5695)

  - By manipulating the text in an <code><input></code> tag, an attacker could have caused corrupt
    memory leading to a potentially exploitable crash. (CVE-2024-5696)

  - A website was able to detect when a user took a screenshot of a page using the built-in Screenshot
    functionality in Firefox. (CVE-2024-5697)

  - By manipulating the fullscreen feature while opening a data-list, an attacker could have overlaid a text
    box over the address bar. This could have led to user confusion and possible spoofing attacks.
    (CVE-2024-5698)

  - In violation of spec, cookie prefixes such as <code>Secure</code> were being ignored if they were not
    correctly capitalized - by spec they should be checked with a case-insensitive comparison. This could have
    resulted in the browser not correctly honoring the behaviors specified by the prefix. (CVE-2024-5699)

  - Memory safety bugs present in Firefox 126, Firefox ESR 115.11, and Thunderbird 115.11. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2024-5700)

  - Memory safety bugs present in Firefox 126. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2024-5701)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-25/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 127.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5695");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'127.0', severity:SECURITY_HOLE);
