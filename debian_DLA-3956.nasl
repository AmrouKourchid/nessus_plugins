#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3956. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211501);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/17");

  script_cve_id("CVE-2018-25047", "CVE-2023-28447", "CVE-2024-35226");

  script_name(english:"Debian dla-3956 : smarty3 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3956 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3956-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    November 17, 2024                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : smarty3
    Version        : 3.1.39-2+deb11u2
    CVE ID         : CVE-2018-25047 CVE-2023-28447 CVE-2024-35226
    Debian Bug     : 1019897 1033964 1072530

    Multiple vulnerabilties were discovered for smarty3, a widely-used PHP
    templating engine, which potentially allows an attacker to perform an
    XSS (e.g JavaScript or PHP code injection).

    CVE-2018-25047

        In Smarty before 3.1.47 and 4.x before 4.2.1,
        libs/plugins/function.mailto.php allows XSS. A web page that uses
        smarty_function_mailto, and that could be parameterized using GET or
        POST input parameters, could allow injection of JavaScript code by a
        user.

    CVE-2023-28447

        In affected versions smarty did not properly escape javascript code.
        An attacker could exploit this vulnerability to execute arbitrary
        JavaScript code in the context of the user's browser session. This
        may lead to unauthorized access to sensitive user data, manipulation
        of the web application's behavior, or unauthorized actions performed
        on behalf of the user. Users are advised to upgrade to either
        version 3.1.48 or to 4.3.1 to resolve this issue. There are no known
        workarounds for this vulnerability.

    CVE-2024-35226

        In affected versions template authors could inject php code by
        choosing a malicious file name for an extends-tag. Sites that cannot
        fully trust template authors should update asap. All users are
        advised to update.  There is no patch for users on the v3 branch.
        There are no known workarounds for this vulnerability.

    For Debian 11 bullseye, these problems have been fixed in version
    3.1.39-2+deb11u2.

    We recommend that you upgrade your smarty3 packages.

    Please note you will have to clear out all smarty generated files after
    installing the update, by default in a templates_c directory.

    For the detailed security status of smarty3 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/smarty3

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/smarty3");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-25047");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28447");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-35226");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/smarty3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the smarty3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28447");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smarty3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'smarty3', 'reference': '3.1.39-2+deb11u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'smarty3');
}
