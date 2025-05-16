#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5723. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(201116);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/09");

  script_cve_id("CVE-2024-36041");

  script_name(english:"Debian dsa-5723 : libcolorcorrect5 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5723
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5723-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    June 27, 2024                         https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : plasma-workspace
    CVE ID         : CVE-2024-36041

    Fabian Vogt discovered that the KDE session management server
    insufficiently restricted ICE connections from localhost, which could
    allow a local attacker to execute arbitrary code as another user on
    next boot.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 4:5.20.5-6+deb11u1.

    For the stable distribution (bookworm), this problem has been fixed in
    version 4:5.27.5-2+deb12u2.

    We recommend that you upgrade your plasma-workspace packages.

    For the detailed security status of plasma-workspace please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/plasma-workspace

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/plasma-workspace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1dd18931");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/plasma-workspace");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-36041");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/plasma-workspace");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libcolorcorrect5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36041");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcolorcorrect5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkfontinst5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkfontinstui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkworkspace5-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnotificationmanager1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplasma-geolocation-interface5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtaskmanager6abi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libweather-ion7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:plasma-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:plasma-workspace-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:plasma-workspace-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:plasma-workspace-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sddm-theme-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sddm-theme-debian-breeze");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
    {'release': '11.0', 'prefix': 'libcolorcorrect5', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'libkfontinst5', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'libkfontinstui5', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'libkworkspace5-5', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'libnotificationmanager1', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'libplasma-geolocation-interface5', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'libtaskmanager6abi1', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'libweather-ion7', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'plasma-workspace', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'plasma-workspace-data', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'plasma-workspace-dev', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'plasma-workspace-wayland', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'sddm-theme-breeze', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '11.0', 'prefix': 'sddm-theme-debian-breeze', 'reference': '4:5.20.5-6+deb11u1'},
    {'release': '12.0', 'prefix': 'libcolorcorrect5', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkfontinst5', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkfontinstui5', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libkworkspace5-5', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libnotificationmanager1', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libplasma-geolocation-interface5', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libtaskmanager6abi1', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'libweather-ion7', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'plasma-workspace', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'plasma-workspace-data', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'plasma-workspace-dev', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'plasma-workspace-wayland', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'sddm-theme-breeze', 'reference': '4:5.27.5-2+deb12u2'},
    {'release': '12.0', 'prefix': 'sddm-theme-debian-breeze', 'reference': '4:5.27.5-2+deb12u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcolorcorrect5 / libkfontinst5 / libkfontinstui5 / libkworkspace5-5 / etc');
}
