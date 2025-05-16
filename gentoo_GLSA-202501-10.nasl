#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202501-10.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(214554);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

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
    "CVE-2024-10467",
    "CVE-2024-10468",
    "CVE-2024-11692",
    "CVE-2024-11694",
    "CVE-2024-11695",
    "CVE-2024-11696",
    "CVE-2024-11697",
    "CVE-2024-11699",
    "CVE-2024-11700",
    "CVE-2024-11701",
    "CVE-2024-11704",
    "CVE-2024-11705",
    "CVE-2024-11706",
    "CVE-2024-11708",
    "CVE-2025-0237",
    "CVE-2025-0238",
    "CVE-2025-0239",
    "CVE-2025-0240",
    "CVE-2025-0241",
    "CVE-2025-0242",
    "CVE-2025-0243",
    "CVE-2025-0247"
  );
  script_xref(name:"IAVA", value:"2025-A-0079-S");

  script_name(english:"GLSA-202501-10 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202501-10 (Mozilla Firefox: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Firefox. Please review the CVE identifiers
    referenced below for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202501-10");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=942469");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=945050");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=948113");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox users should upgrade to the latest version in their release channel:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-134.0:rapid
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-128.6.0:esr

All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-134.0:rapid
          # emerge --ask --oneshot --verbose >=www-client/firefox-128.6.0:esr");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10467");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 128.6.0", "lt 128.0.0"),
    'vulnerable' : make_list("lt 128.6.0")
  },
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 134.0", "lt 129.0.0"),
    'vulnerable' : make_list("lt 134.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 128.6.0", "lt 128.0.0"),
    'vulnerable' : make_list("lt 128.6.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 134.0", "lt 129.0.0"),
    'vulnerable' : make_list("lt 134.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be
# used for each fixed/vulnerable version pair.

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mozilla Firefox');
}
