#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-04.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187653);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/28");

  script_cve_id(
    "CVE-2023-28198",
    "CVE-2023-28204",
    "CVE-2023-32370",
    "CVE-2023-32373",
    "CVE-2023-32393",
    "CVE-2023-32439",
    "CVE-2023-37450",
    "CVE-2023-38133",
    "CVE-2023-38572",
    "CVE-2023-38592",
    "CVE-2023-38594",
    "CVE-2023-38595",
    "CVE-2023-38597",
    "CVE-2023-38599",
    "CVE-2023-38600",
    "CVE-2023-38611",
    "CVE-2023-40397",
    "CVE-2023-42916",
    "CVE-2023-42917"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/12");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/14");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/25");

  script_name(english:"GLSA-202401-04 : WebKitGTK+: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-04 (WebKitGTK+: Multiple Vulnerabilities)

  - A use-after-free issue was addressed with improved memory management. (CVE-2023-28198)

  - An out-of-bounds read was addressed with improved input validation. (CVE-2023-28204)

  - A logic issue was addressed with improved validation. (CVE-2023-32370)

  - A use-after-free issue was addressed with improved memory management. (CVE-2023-32373)

  - The issue was addressed with improved memory handling. (CVE-2023-32393)

  - A type confusion issue was addressed with improved checks. (CVE-2023-32439)

  - The issue was addressed with improved checks. (CVE-2023-37450)

  - The issue was addressed with improved checks. (CVE-2023-38133)

  - The issue was addressed with improved checks. (CVE-2023-38572)

  - A logic issue was addressed with improved restrictions. (CVE-2023-38592)

  - The issue was addressed with improved checks. (CVE-2023-38594)

  - The issue was addressed with improved checks. (CVE-2023-38595, CVE-2023-38600)

  - The issue was addressed with improved checks. (CVE-2023-38597)

  - A logic issue was addressed with improved state management. (CVE-2023-38599)

  - The issue was addressed with improved memory handling. (CVE-2023-38611)

  - The issue was addressed with improved checks. (CVE-2023-40397)

  - An out-of-bounds read was addressed with improved input validation. (CVE-2023-42916)

  - A memory corruption vulnerability was addressed with improved locking. (CVE-2023-42917)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-04");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=907818");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=909663");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=910656");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918087");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918099");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=919290");
  script_set_attribute(attribute:"solution", value:
"All WebKitGTK+ users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-libs/webkit-gtk-2.42.3");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42917");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-40397");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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
    'unaffected' : make_list("ge 2.42.3"),
    'vulnerable' : make_list("lt 2.42.3")
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
