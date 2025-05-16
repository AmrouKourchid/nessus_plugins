#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202501-09.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(214558);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id(
    "CVE-2024-4058",
    "CVE-2024-4059",
    "CVE-2024-4060",
    "CVE-2024-4558",
    "CVE-2024-4559",
    "CVE-2024-4761",
    "CVE-2024-5157",
    "CVE-2024-5158",
    "CVE-2024-5159",
    "CVE-2024-5160",
    "CVE-2024-5830",
    "CVE-2024-5831",
    "CVE-2024-5832",
    "CVE-2024-5833",
    "CVE-2024-5834",
    "CVE-2024-5835",
    "CVE-2024-5836",
    "CVE-2024-5837",
    "CVE-2024-5838",
    "CVE-2024-5839",
    "CVE-2024-5840",
    "CVE-2024-5841",
    "CVE-2024-5842",
    "CVE-2024-5843",
    "CVE-2024-5844",
    "CVE-2024-5845",
    "CVE-2024-5846",
    "CVE-2024-5847",
    "CVE-2024-6290",
    "CVE-2024-6291",
    "CVE-2024-6292",
    "CVE-2024-6293",
    "CVE-2024-6988",
    "CVE-2024-6989",
    "CVE-2024-6991",
    "CVE-2024-6994",
    "CVE-2024-6995",
    "CVE-2024-6996",
    "CVE-2024-6997",
    "CVE-2024-6998",
    "CVE-2024-6999",
    "CVE-2024-7000",
    "CVE-2024-7001",
    "CVE-2024-7003",
    "CVE-2024-7004",
    "CVE-2024-7005",
    "CVE-2024-7532",
    "CVE-2024-7533",
    "CVE-2024-7534",
    "CVE-2024-7535",
    "CVE-2024-7536",
    "CVE-2024-7550",
    "CVE-2024-7964",
    "CVE-2024-7965",
    "CVE-2024-7966",
    "CVE-2024-7967",
    "CVE-2024-7968",
    "CVE-2024-7969",
    "CVE-2024-7971",
    "CVE-2024-7972",
    "CVE-2024-7973",
    "CVE-2024-7974",
    "CVE-2024-7975",
    "CVE-2024-7976",
    "CVE-2024-7977",
    "CVE-2024-7978",
    "CVE-2024-7979",
    "CVE-2024-7980",
    "CVE-2024-7981",
    "CVE-2024-8033",
    "CVE-2024-8034",
    "CVE-2024-8035",
    "CVE-2024-8193",
    "CVE-2024-8194",
    "CVE-2024-8198",
    "CVE-2024-8636",
    "CVE-2024-8637",
    "CVE-2024-8638",
    "CVE-2024-8639",
    "CVE-2024-9120",
    "CVE-2024-9121",
    "CVE-2024-9122",
    "CVE-2024-9123",
    "CVE-2024-9602",
    "CVE-2024-9603",
    "CVE-2024-10229",
    "CVE-2024-10230",
    "CVE-2024-10231",
    "CVE-2024-10826",
    "CVE-2024-10827",
    "CVE-2024-45490",
    "CVE-2024-45491",
    "CVE-2024-45492"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/06");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/16");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/18");

  script_name(english:"GLSA-202501-09 : QtWebEngine: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202501-09 (QtWebEngine: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in QtWebEngine. Please review the CVE identifiers referenced
    below for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202501-09");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=944807");
  script_set_attribute(attribute:"solution", value:
"All QtWebEngine users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-qt/qtwebengine-5.15.16_p20241115");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9603");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-45492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'unaffected' : make_list("ge 5.15.16_p20241115"),
    'vulnerable' : make_list("lt 5.15.16_p20241115")
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
