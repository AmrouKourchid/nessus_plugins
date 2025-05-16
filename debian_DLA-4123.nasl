#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4123. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(234255);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/13");

  script_cve_id("CVE-2022-23303", "CVE-2022-23304", "CVE-2022-37660");

  script_name(english:"Debian dla-4123 : eapoltest - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4123 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4123-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    April 12, 2025                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : wpa
    Version        : 2:2.9.0-21+deb11u3
    CVE ID         : CVE-2022-23303 CVE-2022-23304 CVE-2022-37660

    Multiple vulnerabilities were found in wpa, a set of tools including
    the widely-used wpasupplicant client for authenticating with WPA
    and WPA2 wireless networks.

    CVE-2022-23303

        The implementations of SAE in hostapd
        are vulnerable to side channel attacks as a result of
        cache access patterns.

    CVE-2022-23304

        The implementations of EAP-pwd are vulnerable
        to side-channel attacks as a result of cache access patterns.

    CVE-2022-37660

        The PKEX code remains active even after
        a successful PKEX association. An attacker that successfully
        bootstrapped public keys with another entity using PKEX in
        the past, will be able to subvert a future bootstrapping
        by passively observing public keys.

    For Debian 11 bullseye, these problems have been fixed in version
    2:2.9.0-21+deb11u3.

    We recommend that you upgrade your wpa packages.

    For the detailed security status of wpa please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/wpa

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wpa");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23304");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37660");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wpa");
  script_set_attribute(attribute:"solution", value:
"Upgrade the eapoltest packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eapoltest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpa-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpagui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant-udeb");
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
    {'release': '11.0', 'prefix': 'eapoltest', 'reference': '2:2.9.0-21+deb11u3'},
    {'release': '11.0', 'prefix': 'hostapd', 'reference': '2:2.9.0-21+deb11u3'},
    {'release': '11.0', 'prefix': 'libwpa-client-dev', 'reference': '2:2.9.0-21+deb11u3'},
    {'release': '11.0', 'prefix': 'wpagui', 'reference': '2:2.9.0-21+deb11u3'},
    {'release': '11.0', 'prefix': 'wpasupplicant', 'reference': '2:2.9.0-21+deb11u3'},
    {'release': '11.0', 'prefix': 'wpasupplicant-udeb', 'reference': '2:2.9.0-21+deb11u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eapoltest / hostapd / libwpa-client-dev / wpagui / wpasupplicant / etc');
}
