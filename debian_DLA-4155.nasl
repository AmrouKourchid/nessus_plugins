#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4155. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(235597);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2025-3891");

  script_name(english:"Debian dla-4155 : libapache2-mod-auth-openidc - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by a vulnerability as referenced in the dla-4155
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4155-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Moritz Schlarb
    May 08, 2025                                  https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : libapache2-mod-auth-openidc
    Version        : 2.4.9.4-0+deb11u6
    CVE ID         : CVE-2025-3891
    Debian Bug     : 1104484

    A vulnerability has been fixed in mod_auth_openidc, an OpenID Certified
    authentication and authorization module for the Apache 2.x HTTP server
    that implements the OpenID Connect Relying Party functionality.

    An unauthenticated attacker can crash the Apache httpd process by sending
    a POST request without a Content-Type header when OIDCPreservePost is
    enabled in mod_auth_openidc. This leads to denial of service.

    A workaround is to disable the OIDCPreservePost directive.

    For Debian 11 bullseye, this problem has been fixed in version
    2.4.9.4-0+deb11u6.

    We recommend that you upgrade your libapache2-mod-auth-openidc packages.

    For the detailed security status of libapache2-mod-auth-openidc please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libapache2-mod-auth-openidc

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/libapache2-mod-auth-openidc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0371ebc9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-3891");
  # https://packages.debian.org/source/bullseye/libapache2-mod-auth-openidc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d778800c");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libapache2-mod-auth-openidc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3891");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-auth-openidc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'libapache2-mod-auth-openidc', 'reference': '2.4.9.4-0+deb11u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-auth-openidc');
}
