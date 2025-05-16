#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202409-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(207566);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/22");

  script_cve_id("CVE-2024-7348");

  script_name(english:"GLSA-202409-02 : PostgreSQL: Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202409-02 (PostgreSQL: Privilege Escalation)

    A vulnerability has been discovered in PostgreSQL. Please review the CVE identifier referenced below for
    details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202409-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=937573");
  script_set_attribute(attribute:"solution", value:
"All PostgreSQL users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-12.20:12
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-13.16:13
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-14.13:14
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-15.8:15
          # emerge --ask --oneshot --verbose >=dev-db/postgresql-16.4:16");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7348");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postgresql");
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
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 12.20", "lt 12.0.0"),
    'vulnerable' : make_list("lt 12.20")
  },
  {
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 13.16", "lt 13.0.0"),
    'vulnerable' : make_list("lt 13.16")
  },
  {
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 14.13", "lt 14.0.0"),
    'vulnerable' : make_list("lt 14.13")
  },
  {
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 15.8", "lt 15.0.0"),
    'vulnerable' : make_list("lt 15.8")
  },
  {
    'name' : 'dev-db/postgresql',
    'unaffected' : make_list("ge 16.4", "lt 16.0.0"),
    'vulnerable' : make_list("lt 16.4")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'PostgreSQL');
}
