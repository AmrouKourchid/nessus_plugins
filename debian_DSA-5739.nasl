#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5739. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(205083);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2024-5290");

  script_name(english:"Debian dsa-5739 : eapoltest - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5739
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5739-1                   security@debian.org
    https://www.debian.org/security/                     Salvatore Bonaccorso
    August 06, 2024                       https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : wpa
    CVE ID         : CVE-2024-5290

    Rory McNamara reported a local privilege escalation in wpasupplicant: A
    user able to escalate to the netdev group can load arbitrary shared
    object files in the context of the wpa_supplicant process running as
    root.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 2:2.9.0-21+deb11u2.

    For the stable distribution (bookworm), this problem has been fixed in
    version 2:2.10-12+deb12u2.

    We recommend that you upgrade your wpa packages.

    For the detailed security status of wpa please refer to its security
    tracker page at:
    https://security-tracker.debian.org/tracker/wpa

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wpa");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-5290");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/wpa");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wpa");
  script_set_attribute(attribute:"solution", value:
"Upgrade the eapoltest packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5290");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eapoltest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwpa-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpagui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'eapoltest', 'reference': '2:2.9.0-21+deb11u2'},
    {'release': '11.0', 'prefix': 'hostapd', 'reference': '2:2.9.0-21+deb11u2'},
    {'release': '11.0', 'prefix': 'libwpa-client-dev', 'reference': '2:2.9.0-21+deb11u2'},
    {'release': '11.0', 'prefix': 'wpagui', 'reference': '2:2.9.0-21+deb11u2'},
    {'release': '11.0', 'prefix': 'wpasupplicant', 'reference': '2:2.9.0-21+deb11u2'},
    {'release': '11.0', 'prefix': 'wpasupplicant-udeb', 'reference': '2:2.9.0-21+deb11u2'},
    {'release': '12.0', 'prefix': 'eapoltest', 'reference': '2:2.10-12+deb12u2'},
    {'release': '12.0', 'prefix': 'hostapd', 'reference': '2:2.10-12+deb12u2'},
    {'release': '12.0', 'prefix': 'libwpa-client-dev', 'reference': '2:2.10-12+deb12u2'},
    {'release': '12.0', 'prefix': 'wpagui', 'reference': '2:2.10-12+deb12u2'},
    {'release': '12.0', 'prefix': 'wpasupplicant', 'reference': '2:2.10-12+deb12u2'},
    {'release': '12.0', 'prefix': 'wpasupplicant-udeb', 'reference': '2:2.10-12+deb12u2'}
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
