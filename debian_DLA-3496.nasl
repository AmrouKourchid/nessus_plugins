#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3496. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(178300);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-28862");

  script_name(english:"Debian dla-3496 : lemonldap-ng - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3496
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3496-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    July 14, 2023                                 https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : lemonldap-ng
    Version        : 2.0.2+ds-7+deb10u9
    CVE ID         : CVE-2023-28862

    Issues were discovered in Lemonldap::NG, an OpenID-Connect, CAS and SAML
    compatible Web-SSO system, which could lead to impersonation of users
    with a second factor authentication.

    Weak session ID generation in the AuthBasic handler and incorrect
    failure handling during a password check allow attackers to bypass 2FA
    verification.  Any plugin that tries to deny session creation after the
    store step does not deny an AuthBasic session.

    Using the AuthBasic handler is now refused for users with a second
    factor.  Admins who are *absolutely sure* that such accounts should be
    able to use AuthBasic handlers (which are password only) can append `and
    not $ENV{AuthBasic}` to the 2FA activation rules.

    For Debian 10 buster, these problems have been fixed in version
    2.0.2+ds-7+deb10u9.

    We recommend that you upgrade your lemonldap-ng packages.

    For the detailed security status of lemonldap-ng please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/lemonldap-ng

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/lemonldap-ng
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f8cb51e");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28862");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/lemonldap-ng");
  script_set_attribute(attribute:"solution", value:
"Upgrade the lemonldap-ng packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng-fastcgi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng-handler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lemonldap-ng-uwsgi-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-common-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-handler-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-manager-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblemonldap-ng-portal-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'lemonldap-ng', 'reference': '2.0.2+ds-7+deb10u9'},
    {'release': '10.0', 'prefix': 'lemonldap-ng-doc', 'reference': '2.0.2+ds-7+deb10u9'},
    {'release': '10.0', 'prefix': 'lemonldap-ng-fastcgi-server', 'reference': '2.0.2+ds-7+deb10u9'},
    {'release': '10.0', 'prefix': 'lemonldap-ng-handler', 'reference': '2.0.2+ds-7+deb10u9'},
    {'release': '10.0', 'prefix': 'lemonldap-ng-uwsgi-app', 'reference': '2.0.2+ds-7+deb10u9'},
    {'release': '10.0', 'prefix': 'liblemonldap-ng-common-perl', 'reference': '2.0.2+ds-7+deb10u9'},
    {'release': '10.0', 'prefix': 'liblemonldap-ng-handler-perl', 'reference': '2.0.2+ds-7+deb10u9'},
    {'release': '10.0', 'prefix': 'liblemonldap-ng-manager-perl', 'reference': '2.0.2+ds-7+deb10u9'},
    {'release': '10.0', 'prefix': 'liblemonldap-ng-portal-perl', 'reference': '2.0.2+ds-7+deb10u9'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lemonldap-ng / lemonldap-ng-doc / lemonldap-ng-fastcgi-server / etc');
}
