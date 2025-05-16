#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4021. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(214393);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/20");

  script_cve_id(
    "CVE-2021-3514",
    "CVE-2021-3652",
    "CVE-2021-4091",
    "CVE-2022-0918",
    "CVE-2022-0996",
    "CVE-2022-2850",
    "CVE-2024-2199",
    "CVE-2024-3657",
    "CVE-2024-5953",
    "CVE-2024-8445"
  );

  script_name(english:"Debian dla-4021 : 389-ds - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4021 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4021-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Andrej Shadura
    January 19, 2025                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : 389-ds-base
    Version        : 1.4.4.11-2+deb11u1
    CVE ID         : CVE-2021-3652 CVE-2021-4091 CVE-2022-0918 CVE-2022-0996
                     CVE-2022-2850 CVE-2024-2199 CVE-2024-3657 CVE-2024-5953
                     CVE-2024-8445

    This update fixes multiple vulnerabilities in 389-ds-base LDAP server.

    CVE-2021-3652

        If an asterisk is imported as password hashes, either accidentally
        or maliciously, then instead of being inactive, any password will
        successfully match during authentication. This flaw allows an attacker
        to successfully authenticate as a user whose password was disabled.

    CVE-2021-4091

        A double-free was found in the way 389-ds-base handles virtual
        attributes context in persistent searches. An attacker could send a
        series of search requests, forcing the server to behave unexpectedly,
        and crash.

    CVE-2022-0918

        A vulnerability allows an unauthenticated attacker with network
        access to the LDAP port to cause a denial of service. The denial of
        service is triggered by a single message sent over a TCP connection,
        no bind or other authentication is required. The message triggers
        a segmentation fault that results in slapd crashing.

    CVE-2022-0996

        A vulnerability allows expired passwords to access the database to
        cause improper authentication.

    CVE-2022-2850

        When the content synchronization plugin is enabled, an authenticated
        user can reach a NULL pointer dereference using a specially
        crafted query. This flaw allows an authenticated attacker to cause
        a denial of service. This CVE is assigned against an incomplete fix
        of CVE-2021-3514.

    CVE-2024-2199

        A denial of service vulnerability that may allow an authenticated
        user to cause a server crash while modifying `userPassword` using
        malformed input.

    CVE-2024-3657

        A specially-crafted LDAP query can potentially cause a failure on
        the directory server, leading to a denial of service.

    CVE-2024-5953

        This issue may allow an authenticated user to cause a server denial
        of service while attempting to log in with a user with a malformed
        hash in their password.

    CVE-2024-8445

        The fix for CVE-2024-2199 in 389-ds-base was insufficient to cover
        all scenarios. In certain product versions, an authenticated user
        may cause a server crash while modifying `userPassword` using
        malformed input.

    For Debian 11 bullseye, these problems have been fixed in version
    1.4.4.11-2+deb11u1.

    We recommend that you upgrade your 389-ds-base packages.

    For the detailed security status of 389-ds-base please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/389-ds-base

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/389-ds-base");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3514");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3652");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4091");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0918");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-2199");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-3657");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-5953");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-8445");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/389-ds-base");
  script_set_attribute(attribute:"solution", value:
"Upgrade the 389-ds packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3652");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0996");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cockpit-389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-lib389");
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
    {'release': '11.0', 'prefix': '389-ds', 'reference': '1.4.4.11-2+deb11u1'},
    {'release': '11.0', 'prefix': '389-ds-base', 'reference': '1.4.4.11-2+deb11u1'},
    {'release': '11.0', 'prefix': '389-ds-base-dev', 'reference': '1.4.4.11-2+deb11u1'},
    {'release': '11.0', 'prefix': '389-ds-base-libs', 'reference': '1.4.4.11-2+deb11u1'},
    {'release': '11.0', 'prefix': 'cockpit-389-ds', 'reference': '1.4.4.11-2+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-lib389', 'reference': '1.4.4.11-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, '389-ds / 389-ds-base / 389-ds-base-dev / 389-ds-base-libs / etc');
}
