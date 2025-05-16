#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-33.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(189847);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/15");

  script_cve_id(
    "CVE-2023-32359",
    "CVE-2023-35074",
    "CVE-2023-39434",
    "CVE-2023-39928",
    "CVE-2023-40451",
    "CVE-2023-41074",
    "CVE-2023-41983",
    "CVE-2023-41993",
    "CVE-2023-42852",
    "CVE-2023-42890"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/16");

  script_name(english:"GLSA-202401-33 : WebKitGTK+: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-33 (WebKitGTK+: Multiple Vulnerabilities)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in iOS
    16.7.2 and iPadOS 16.7.2. A user's password may be read aloud by VoiceOver. (CVE-2023-32359)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 17, Safari 17, watchOS
    10, iOS 17 and iPadOS 17, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-35074)

  - A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 17 and
    iPadOS 17, watchOS 10, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-39434)

  - A use-after-free vulnerability exists in the MediaRecorder API of Webkit WebKitGTK 2.40.5. A specially
    crafted web page can abuse this vulnerability to cause memory corruption and potentially arbitrary code
    execution. A user would need to to visit a malicious webpage to trigger this vulnerability.
    (CVE-2023-39928)

  - This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in Safari 17. An
    attacker with JavaScript execution may be able to execute arbitrary code. (CVE-2023-40451)

  - The issue was addressed with improved checks. This issue is fixed in tvOS 17, Safari 17, watchOS 10, iOS
    17 and iPadOS 17, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-41074)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.1, Safari
    17.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1. Processing web content may lead to a denial-
    of-service. (CVE-2023-41983)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14. Processing web
    content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been
    actively exploited against versions of iOS before iOS 16.7. (CVE-2023-41993)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 17.1 and iPadOS 17.1, watchOS
    10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Sonoma 14.1, Safari 17.1, tvOS 17.1. Processing web content may
    lead to arbitrary code execution. (CVE-2023-42852)

  - The issue was addressed with improved memory handling. This issue is fixed in Safari 17.2, macOS Sonoma
    14.2, watchOS 10.2, iOS 17.2 and iPadOS 17.2, tvOS 17.2. Processing web content may lead to arbitrary code
    execution. (CVE-2023-42890)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-33");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=915222");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918667");
  script_set_attribute(attribute:"solution", value:
"All WebKitGTK+ users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-libs/webkit-gtk-2.42.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42890");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
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
    'name' : 'net-libs/webkit-gtk',
    'unaffected' : make_list("ge 2.42.2"),
    'vulnerable' : make_list("lt 2.42.2")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'WebKitGTK+');
}
