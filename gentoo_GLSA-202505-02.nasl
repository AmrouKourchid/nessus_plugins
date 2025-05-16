#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202505-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(235705);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id(
    "CVE-2024-43097",
    "CVE-2025-1931",
    "CVE-2025-1932",
    "CVE-2025-1933",
    "CVE-2025-1934",
    "CVE-2025-1935",
    "CVE-2025-1936",
    "CVE-2025-1937",
    "CVE-2025-1938",
    "CVE-2025-1941",
    "CVE-2025-1942",
    "CVE-2025-1943",
    "CVE-2025-3028",
    "CVE-2025-3029",
    "CVE-2025-3030",
    "CVE-2025-3031",
    "CVE-2025-3032",
    "CVE-2025-3034",
    "CVE-2025-3035"
  );

  script_name(english:"GLSA-202505-02 : Mozilla Firefox: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202505-02 (Mozilla Firefox: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Firefox. Please review the CVE identifiers
    referenced below for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202505-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=951563");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=953021");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Firefox users should upgrade to the latest version in their release channel:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-137.0.1:rapid
          # emerge --ask --oneshot --verbose >=www-client/firefox-bin-128.9.0:esr
        
All Mozilla Firefox users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-client/firefox-137.0.1:rapid
          # emerge --ask --oneshot --verbose >=www-client/firefox-128.9.0:esr");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3030");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-1942");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
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
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 128.9.0", "lt 128.0.0"),
    'vulnerable' : make_list("lt 128.9.0")
  },
  {
    'name' : 'www-client/firefox',
    'unaffected' : make_list("ge 137.0.1", "lt 137.0.0"),
    'vulnerable' : make_list("lt 137.0.1")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 128.9.0", "lt 128.0.0"),
    'vulnerable' : make_list("lt 128.9.0")
  },
  {
    'name' : 'www-client/firefox-bin',
    'unaffected' : make_list("ge 137.0.1", "lt 137.0.0"),
    'vulnerable' : make_list("lt 137.0.1")
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
