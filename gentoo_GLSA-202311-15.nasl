#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202311-15.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(186284);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/26");

  script_cve_id("CVE-2023-0950", "CVE-2023-2255");

  script_name(english:"GLSA-202311-15 : LibreOffice: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202311-15 (LibreOffice: Multiple Vulnerabilities)

  - Improper Validation of Array Index vulnerability in the spreadsheet component of The Document Foundation
    LibreOffice allows an attacker to craft a spreadsheet document that will cause an array index underflow
    when loaded. In the affected versions of LibreOffice certain malformed spreadsheet formulas, such as
    AGGREGATE, could be created with less parameters passed to the formula interpreter than it expected,
    leading to an array index underflow, in which case there is a risk that arbitrary code could be executed.
    This issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.6; 7.5 versions prior to
    7.5.1. (CVE-2023-0950)

  - Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to
    craft a document that would cause external links to be loaded without prompt. In the affected versions of
    LibreOffice documents that used floating frames linked to external files, would load the contents of
    those frames without prompting the user for permission to do so. This was inconsistent with the treatment
    of other linked content in LibreOffice. This issue affects: The Document Foundation LibreOffice 7.4
    versions prior to 7.4.7; 7.5 versions prior to 7.5.3. (CVE-2023-2255)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202311-15");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=908083");
  script_set_attribute(attribute:"solution", value:
"All LibreOffice binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-office/libreoffice-bin-7.5.3.2
        
All LibreOffice users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-office/libreoffice-7.5.3.2");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'app-office/libreoffice',
    'unaffected' : make_list("ge 7.5.3.2"),
    'vulnerable' : make_list("lt 7.5.3.2")
  },
  {
    'name' : 'app-office/libreoffice-bin',
    'unaffected' : make_list("ge 7.5.3.2"),
    'vulnerable' : make_list("lt 7.5.3.2")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'LibreOffice');
}
