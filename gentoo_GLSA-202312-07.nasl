#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202312-07.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187218);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/06");

  script_cve_id(
    "CVE-2023-4068",
    "CVE-2023-4069",
    "CVE-2023-4070",
    "CVE-2023-4071",
    "CVE-2023-4072",
    "CVE-2023-4073",
    "CVE-2023-4074",
    "CVE-2023-4075",
    "CVE-2023-4076",
    "CVE-2023-4077",
    "CVE-2023-4078",
    "CVE-2023-4761",
    "CVE-2023-4762",
    "CVE-2023-4763",
    "CVE-2023-4764",
    "CVE-2023-5218",
    "CVE-2023-5473",
    "CVE-2023-5474",
    "CVE-2023-5475",
    "CVE-2023-5476",
    "CVE-2023-5477",
    "CVE-2023-5478",
    "CVE-2023-5479",
    "CVE-2023-5480",
    "CVE-2023-5481",
    "CVE-2023-5482",
    "CVE-2023-5483",
    "CVE-2023-5484",
    "CVE-2023-5485",
    "CVE-2023-5486",
    "CVE-2023-5487",
    "CVE-2023-5849",
    "CVE-2023-5850",
    "CVE-2023-5851",
    "CVE-2023-5852",
    "CVE-2023-5853",
    "CVE-2023-5854",
    "CVE-2023-5855",
    "CVE-2023-5856",
    "CVE-2023-5857",
    "CVE-2023-5858",
    "CVE-2023-5859",
    "CVE-2023-5996",
    "CVE-2023-5997",
    "CVE-2023-6112"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/27");

  script_name(english:"GLSA-202312-07 : QtWebEngine: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202312-07 (QtWebEngine: Multiple Vulnerabilities)

  - Type Confusion in V8 in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to perform
    arbitrary read/write via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4068,
    CVE-2023-4070)

  - Type Confusion in V8 in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4069)

  - Heap buffer overflow in Visuals in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4071)

  - Out of bounds read and write in WebGL in Google Chrome prior to 115.0.5790.170 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4072)

  - Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 115.0.5790.170 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-4073)

  - Use after free in Blink Task Scheduling in Google Chrome prior to 115.0.5790.170 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4074)

  - Use after free in Cast in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4075)

  - Use after free in WebRTC in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted WebRTC session. (Chromium security severity: High) (CVE-2023-4076)

  - Insufficient data validation in Extensions in Google Chrome prior to 115.0.5790.170 allowed an attacker
    who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via
    a crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-4077)

  - Inappropriate implementation in Extensions in Google Chrome prior to 115.0.5790.170 allowed an attacker
    who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via
    a crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-4078)

  - Out of bounds memory access in FedCM in Google Chrome prior to 116.0.5845.179 allowed a remote attacker
    who had compromised the renderer process to perform an out of bounds memory read via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-4761)

  - Type Confusion in V8 in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to execute
    arbitrary code via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4762)

  - Use after free in Networks in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4763)

  - Incorrect security UI in BFCache in Google Chrome prior to 116.0.5845.179 allowed a remote attacker to
    spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4764)

  - Use after free in Site Isolation in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-5218)

  - Use after free in Cast in Google Chrome prior to 118.0.5993.70 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Low) (CVE-2023-5473)

  - Heap buffer overflow in PDF in Google Chrome prior to 118.0.5993.70 allowed a remote attacker who
    convinced a user to engage in specific user interactions to potentially exploit heap corruption via a
    crafted PDF file. (Chromium security severity: Medium) (CVE-2023-5474)

  - Inappropriate implementation in DevTools in Google Chrome prior to 118.0.5993.70 allowed an attacker who
    convinced a user to install a malicious extension to bypass discretionary access control via a crafted
    Chrome Extension. (Chromium security severity: Medium) (CVE-2023-5475)

  - Use after free in Blink History in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5476)

  - Inappropriate implementation in Installer in Google Chrome prior to 118.0.5993.70 allowed a local attacker
    to bypass discretionary access control via a crafted command. (Chromium security severity: Low)
    (CVE-2023-5477)

  - Inappropriate implementation in Autofill in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5478)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 118.0.5993.70 allowed an attacker
    who convinced a user to install a malicious extension to bypass an enterprise policy via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-5479)

  - Inappropriate implementation in Payments in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to bypass XSS preventions via a malicious file. (Chromium security severity: High)
    (CVE-2023-5480)

  - Inappropriate implementation in Downloads in Google Chrome prior to 118.0.5993.70 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5481)

  - Insufficient data validation in USB in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5482)

  - Inappropriate implementation in Intents in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to bypass content security policy via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5483)

  - Inappropriate implementation in Navigation in Google Chrome prior to 118.0.5993.70 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5484)

  - Inappropriate implementation in Autofill in Google Chrome prior to 118.0.5993.70 allowed a remote attacker
    to bypass autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5485)

  - Inappropriate implementation in Input in Google Chrome prior to 118.0.5993.70 allowed a remote attacker to
    spoof security UI via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-5486)

  - Inappropriate implementation in Fullscreen in Google Chrome prior to 118.0.5993.70 allowed an attacker who
    convinced a user to install a malicious extension to bypass navigation restrictions via a crafted Chrome
    Extension. (Chromium security severity: Medium) (CVE-2023-5487)

  - Integer overflow in USB in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-5849)

  - Incorrect security UI in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    perform domain spoofing via a crafted domain name. (Chromium security severity: Medium) (CVE-2023-5850)

  - Inappropriate implementation in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5851)

  - Use after free in Printing in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5852)

  - Incorrect security UI in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-5853)

  - Use after free in Profiles in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5854)

  - Use after free in Reading Mode in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5855)

  - Use after free in Side Panel in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-5856)

  - Inappropriate implementation in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to potentially execute arbitrary code via a malicious file. (Chromium security severity: Medium)
    (CVE-2023-5857)

  - Inappropriate implementation in WebApp Provider in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-5858)

  - Incorrect security UI in Picture In Picture in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to perform domain spoofing via a crafted local HTML page. (Chromium security severity: Low)
    (CVE-2023-5859)

  - Use after free in WebAudio in Google Chrome prior to 119.0.6045.123 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5996)

  - Use after free in Garbage Collection in Google Chrome prior to 119.0.6045.159 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5997)

  - Use after free in Navigation in Google Chrome prior to 119.0.6045.159 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6112)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202312-07");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=913050");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915465");
  script_set_attribute(attribute:"solution", value:
"All QtWebEngine users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-qt/qtwebengine-5.15.11_p20231120");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6112");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'dev-qt/qtwebengine',
    'unaffected' : make_list("ge 5.15.11_p20231120"),
    'vulnerable' : make_list("lt 5.15.11_p20231120")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'QtWebEngine');
}
