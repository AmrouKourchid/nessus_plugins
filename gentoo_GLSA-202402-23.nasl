#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-23.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(190763);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/20");

  script_cve_id(
    "CVE-2024-0333",
    "CVE-2024-0517",
    "CVE-2024-0518",
    "CVE-2024-0519",
    "CVE-2024-0804",
    "CVE-2024-0805",
    "CVE-2024-0806",
    "CVE-2024-0807",
    "CVE-2024-0808",
    "CVE-2024-0809",
    "CVE-2024-0810",
    "CVE-2024-0811",
    "CVE-2024-0812",
    "CVE-2024-0813",
    "CVE-2024-0814",
    "CVE-2024-1059",
    "CVE-2024-1060",
    "CVE-2024-1077"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/07");

  script_name(english:"GLSA-202402-23 : Chromium, Google Chrome, Microsoft Edge: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-23 (Chromium, Google Chrome, Microsoft Edge:
Multiple Vulnerabilities)

  - Insufficient data validation in Extensions in Google Chrome prior to 120.0.6099.216 allowed an attacker in
    a privileged network position to install a malicious extension via a crafted HTML page. (Chromium security
    severity: High) (CVE-2024-0333)

  - Out of bounds write in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0517)

  - Type confusion in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-0518)

  - Out of bounds memory access in V8 in Google Chrome prior to 120.0.6099.224 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0519)

  - Insufficient policy enforcement in iOS Security UI in Google Chrome prior to 121.0.6167.85 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-0804)

  - Inappropriate implementation in Downloads in Google Chrome prior to 121.0.6167.85 allowed a remote
    attacker to perform domain spoofing via a crafted domain name. (Chromium security severity: Medium)
    (CVE-2024-0805)

  - Use after free in Passwords in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via specific UI interaction. (Chromium security severity: Medium)
    (CVE-2024-0806)

  - Use after free in Web Audio in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0807)

  - Integer underflow in WebUI in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially exploit heap corruption via a malicious file. (Chromium security severity: High)
    (CVE-2024-0808)

  - Inappropriate implementation in Autofill in Google Chrome prior to 121.0.6167.85 allowed a remote attacker
    to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-0809)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 121.0.6167.85 allowed an attacker
    who convinced a user to install a malicious extension to leak cross-origin data via a crafted Chrome
    Extension. (Chromium security severity: Medium) (CVE-2024-0810)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 121.0.6167.85 allowed an attacker
    who convinced a user to install a malicious extension to leak cross-origin data via a crafted Chrome
    Extension. (Chromium security severity: Low) (CVE-2024-0811)

  - Inappropriate implementation in Accessibility in Google Chrome prior to 121.0.6167.85 allowed a remote
    attacker to potentially exploit object corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2024-0812)

  - Use after free in Reading Mode in Google Chrome prior to 121.0.6167.85 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific UI interaction.
    (Chromium security severity: Medium) (CVE-2024-0813)

  - Incorrect security UI in Payments in Google Chrome prior to 121.0.6167.85 allowed a remote attacker to
    potentially spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-0814)

  - Use after free in Peer Connection in Google Chrome prior to 121.0.6167.139 allowed a remote attacker to
    potentially exploit stack corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-1059)

  - Use after free in Canvas in Google Chrome prior to 121.0.6167.139 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-1060)

  - Use after free in Network in Google Chrome prior to 121.0.6167.139 allowed a remote attacker to
    potentially exploit heap corruption via a malicious file. (Chromium security severity: High)
    (CVE-2024-1077)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-23");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=922062");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=922340");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=922903");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=923370");
  script_set_attribute(attribute:"solution", value:
"All Google Chrome users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/google-chrome-121.0.6167.139
        
All Chromium users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/chromium-121.0.6167.139
        
All Microsoft Edge users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/microsoft-edge-121.0.2277.83");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1077");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-0808");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:microsoft-edge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'www-client/chromium',
    'unaffected' : make_list("ge 121.0.6167.139"),
    'vulnerable' : make_list("lt 121.0.6167.139")
  },
  {
    'name' : 'www-client/google-chrome',
    'unaffected' : make_list("ge 121.0.6167.139"),
    'vulnerable' : make_list("lt 121.0.6167.139")
  },
  {
    'name' : 'www-client/microsoft-edge',
    'unaffected' : make_list("ge 121.0.2277.83"),
    'vulnerable' : make_list("lt 121.0.2277.83")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Chromium / Google Chrome / Microsoft Edge');
}
