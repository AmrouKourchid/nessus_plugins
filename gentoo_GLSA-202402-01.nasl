#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-01.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(189928);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id(
    "CVE-2023-5156",
    "CVE-2023-6246",
    "CVE-2023-6779",
    "CVE-2023-6780"
  );

  script_name(english:"GLSA-202402-01 : glibc: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-01 (glibc: Multiple Vulnerabilities)

  - A flaw was found in the GNU C Library. A recent fix for CVE-2023-4806 introduced the potential for a
    memory leak, which may result in an application crash. (CVE-2023-5156)

  - A heap-based buffer overflow was found in the __vsyslog_internal function of the glibc library. This
    function is called by the syslog and vsyslog functions. This issue occurs when the openlog function was
    not called, or called with the ident argument set to NULL, and the program name (the basename of argv[0])
    is bigger than 1024 bytes, resulting in an application crash or local privilege escalation. This issue
    affects glibc 2.36 and newer. (CVE-2023-6246)

  - An off-by-one heap-based buffer overflow was found in the __vsyslog_internal function of the glibc
    library. This function is called by the syslog and vsyslog functions. This issue occurs when these
    functions are called with a message bigger than INT_MAX bytes, leading to an incorrect calculation of the
    buffer size to store the message, resulting in an application crash. This issue affects glibc 2.37 and
    newer. (CVE-2023-6779)

  - An integer overflow was found in the __vsyslog_internal function of the glibc library. This function is
    called by the syslog and vsyslog functions. This issue occurs when these functions are called with a very
    long message, leading to an incorrect calculation of the buffer size to store the message, resulting in
    undefined behavior. This issue affects glibc 2.37 and newer. (CVE-2023-6780)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-01");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918412");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=923352");
  script_set_attribute(attribute:"solution", value:
"All glibc users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=sys-libs/glibc-2.38-r10");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:glibc");
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
    'name' : 'sys-libs/glibc',
    'unaffected' : make_list("ge 2.38-r10"),
    'vulnerable' : make_list("lt 2.38-r10")
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
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc');
}
