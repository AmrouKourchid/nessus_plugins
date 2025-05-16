#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-14.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(190672);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/18");

  script_cve_id(
    "CVE-2023-5997",
    "CVE-2023-6112",
    "CVE-2023-6345",
    "CVE-2023-6346",
    "CVE-2023-6347",
    "CVE-2023-6348",
    "CVE-2023-6350",
    "CVE-2023-6351",
    "CVE-2023-6508",
    "CVE-2023-6509",
    "CVE-2023-6510",
    "CVE-2023-6511",
    "CVE-2023-6512",
    "CVE-2023-6702",
    "CVE-2023-6703",
    "CVE-2023-6704",
    "CVE-2023-6705",
    "CVE-2023-6706",
    "CVE-2023-6707",
    "CVE-2023-7024",
    "CVE-2024-0222",
    "CVE-2024-0223",
    "CVE-2024-0224",
    "CVE-2024-0225",
    "CVE-2024-0333",
    "CVE-2024-0517",
    "CVE-2024-0518",
    "CVE-2024-0519"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/21");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/01/23");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/07");

  script_name(english:"GLSA-202402-14 : QtWebEngine: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-14 (QtWebEngine: Multiple Vulnerabilities)

  - Use after free in Garbage Collection in Google Chrome prior to 119.0.6045.159 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5997)

  - Use after free in Navigation in Google Chrome prior to 119.0.6045.159 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6112)

  - Integer overflow in Skia in Google Chrome prior to 119.0.6045.199 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a malicious file. (Chromium
    security severity: High) (CVE-2023-6345)

  - Use after free in WebAudio in Google Chrome prior to 119.0.6045.199 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6346)

  - Use after free in Mojo in Google Chrome prior to 119.0.6045.199 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-6347)

  - Type Confusion in Spellcheck in Google Chrome prior to 119.0.6045.199 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-6348)

  - Use after free in libavif in Google Chrome prior to 119.0.6045.199 allowed a remote attacker to
    potentially exploit heap corruption via a crafted avif file. (Chromium security severity: High)
    (CVE-2023-6350, CVE-2023-6351)

  - Use after free in Media Stream in Google Chrome prior to 120.0.6099.62 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-6508)

  - Use after free in Side Panel Search in Google Chrome prior to 120.0.6099.62 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    UI interaction. (Chromium security severity: High) (CVE-2023-6509)

  - Use after free in Media Capture in Google Chrome prior to 120.0.6099.62 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    UI interaction. (Chromium security severity: Medium) (CVE-2023-6510)

  - Inappropriate implementation in Autofill in Google Chrome prior to 120.0.6099.62 allowed a remote attacker
    to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-6511)

  - Inappropriate implementation in Web Browser UI in Google Chrome prior to 120.0.6099.62 allowed a remote
    attacker to potentially spoof the contents of an iframe dialog context menu via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2023-6512)

  - Type confusion in V8 in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-6702)

  - Use after free in Blink in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-6703)

  - Use after free in libavif in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to
    potentially exploit heap corruption via a crafted image file. (Chromium security severity: High)
    (CVE-2023-6704)

  - Use after free in WebRTC in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-6705)

  - Use after free in FedCM in Google Chrome prior to 120.0.6099.109 allowed a remote attacker who convinced a
    user to engage in specific UI interaction to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-6706)

  - Use after free in CSS in Google Chrome prior to 120.0.6099.109 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-6707)

  - Heap buffer overflow in WebRTC in Google Chrome prior to 120.0.6099.129 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-7024)

  - Use after free in ANGLE in Google Chrome prior to 120.0.6099.199 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2024-0222)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 120.0.6099.199 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0223)

  - Use after free in WebAudio in Google Chrome prior to 120.0.6099.199 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-0224)

  - Use after free in WebGPU in Google Chrome prior to 120.0.6099.199 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-0225)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-14");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=922189");
  script_set_attribute(attribute:"solution", value:
"All QtWebEngine users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-qt/qtwebengine-5.15.12_p20240122");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0519");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-6345");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qtwebengine");
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
    'name' : 'dev-qt/qtwebengine',
    'unaffected' : make_list("ge 5.15.12_p20240122"),
    'vulnerable' : make_list("lt 5.15.12_p20240122")
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
