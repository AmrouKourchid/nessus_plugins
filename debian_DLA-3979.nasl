#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3979. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211976);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/30");

  script_cve_id("CVE-2024-48933", "CVE-2024-52946", "CVE-2024-52947");

  script_name(english:"Debian dla-3979 : lemonldap-ng - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3979 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3979-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    November 30, 2024                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : lemonldap-ng
    Version        : 2.0.11+ds-4+deb11u6
    CVE ID         : CVE-2024-48933 CVE-2024-52946 CVE-2024-52947
    Debian Bug     : 1084979

    Multiple vulnerabilities were discovered in Lemonldap::NG, an
    OpenID-Connect, CAS and SAML compatible Web-SSO system, which could lead
    to injection of arbitrary scripts or authorization bypass.

    CVE-2024-48933

        Cross-site scripting (XSS) vulnerability which allows remote
        attackers to inject arbitrary web script or HTML into the login page
        via a username if userControl has been set to a non-default value
        that allows special HTML characters.

    CVE-2024-52946

        Improper Check during session refresh which allows an authenticated
        user to raise their authentication level if the admin configured an
        Adaptative authentication rule with an increment instead of an
        absolute value.

    CVE-2024-52947

        Cross-site scripting (XSS) vulnerability which allows remote
        attackers to inject arbitrary web script or HTML via the url
        parameter of the upgrade session confirmation page (upgradeSession)
        if the Upgrade session plugin has been enabled by an admin.

    For Debian 11 bullseye, these problems have been fixed in version
    2.0.11+ds-4+deb11u6.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/lemonldap-ng
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f8cb51e");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-48933");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52947");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/lemonldap-ng");
  script_set_attribute(attribute:"solution", value:
"Upgrade the lemonldap-ng packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-48933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/30");

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
    {'release': '11.0', 'prefix': 'lemonldap-ng', 'reference': '2.0.11+ds-4+deb11u6'},
    {'release': '11.0', 'prefix': 'lemonldap-ng-doc', 'reference': '2.0.11+ds-4+deb11u6'},
    {'release': '11.0', 'prefix': 'lemonldap-ng-fastcgi-server', 'reference': '2.0.11+ds-4+deb11u6'},
    {'release': '11.0', 'prefix': 'lemonldap-ng-handler', 'reference': '2.0.11+ds-4+deb11u6'},
    {'release': '11.0', 'prefix': 'lemonldap-ng-uwsgi-app', 'reference': '2.0.11+ds-4+deb11u6'},
    {'release': '11.0', 'prefix': 'liblemonldap-ng-common-perl', 'reference': '2.0.11+ds-4+deb11u6'},
    {'release': '11.0', 'prefix': 'liblemonldap-ng-handler-perl', 'reference': '2.0.11+ds-4+deb11u6'},
    {'release': '11.0', 'prefix': 'liblemonldap-ng-manager-perl', 'reference': '2.0.11+ds-4+deb11u6'},
    {'release': '11.0', 'prefix': 'liblemonldap-ng-portal-perl', 'reference': '2.0.11+ds-4+deb11u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lemonldap-ng / lemonldap-ng-doc / lemonldap-ng-fastcgi-server / etc');
}
