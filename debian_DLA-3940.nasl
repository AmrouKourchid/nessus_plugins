#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3940. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(209887);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/31");

  script_cve_id("CVE-2024-9632");

  script_name(english:"Debian dla-3940 : xdmx - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dla-3940
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3940-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                    Thorsten Alteholz
    October 29, 2024                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : xorg-server
    Version        : 2:1.20.11-1+deb11u14
    CVE ID         : CVE-2024-9632


    Jan-Niklas Sohn working with Trend Micro Zero Day Initiative found an
    issue in the X server and Xwayland implementations published by X.Org.
    CVE-2024-9632 can be triggered by providing a modified bitmap to the X.Org
    server. This may lead to local privilege escalation if the server is run
    as root or remote code execution (e.g. x11 over ssh).



    For Debian 11 bullseye, this problem has been fixed in version
    2:1.20.11-1+deb11u14.

    We recommend that you upgrade your xorg-server packages.

    For the detailed security status of xorg-server please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/xorg-server

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently as

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xorg-server");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-9632");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/xorg-server");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xdmx packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xdmx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-core-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xserver-xorg-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xwayland");
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
    {'release': '11.0', 'prefix': 'xdmx', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xdmx-tools', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xnest', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xorg-server-source', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xserver-common', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xserver-xephyr', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xserver-xorg-core', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xserver-xorg-core-udeb', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xserver-xorg-dev', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xserver-xorg-legacy', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xvfb', 'reference': '2:1.20.11-1+deb11u14'},
    {'release': '11.0', 'prefix': 'xwayland', 'reference': '2:1.20.11-1+deb11u14'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xdmx / xdmx-tools / xnest / xorg-server-source / xserver-common / etc');
}
