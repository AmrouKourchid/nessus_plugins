#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4070. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216929);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2022-24882", "CVE-2022-39320");

  script_name(english:"Debian dla-4070 : freerdp2-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4070 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4070-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    February 27, 2025                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : freerdp2
    Version        : 2.3.0+dfsg1-2+deb11u3
    CVE ID         : CVE-2022-24882 CVE-2022-39320
    Debian Bug     : 1024511 1098355

    Multiple vulnerabilties have been found in freelrdp2, a free
    implementation of the Remote Desktop Protocol (RDP) which
    potentially allows potential buffer overreads or not properly abort
    NTLM authentication on empty password, if used as server.

    Additonally this update fixes a regression with DLA-4053-1 affecting
    drive sharing.

    CVE-2022-24882

      FreeRDP is a free implementation of the Remote Desktop Protocol
      (RDP). In versions prior to 2.7.0, NT LAN Manager (NTLM)
      authentication does not properly abort when someone provides and
      empty password value. This issue affects
      FreeRDP based RDP Server implementations. RDP clients are not
      affected.

    CVE-2022-39320

      FreeRDP is a free remote desktop protocol library and clients.
      Affected versions of FreeRDP may attempt integer addition on too
      narrow types leads to allocation of a buffer too small holding the
      data written. A malicious server can trick a FreeRDP based client to
      read out of bound data and send it back to the server. This issue
      has been addressed in version 2.9.0 and all users are advised to
      upgrade. Users unable to upgrade should not use the `/usb`
      redirection switch.

    For Debian 11 bullseye, these problems have been fixed in version
    2.3.0+dfsg1-2+deb11u3.

    We recommend that you upgrade your freerdp2 packages.

    For the detailed security status of freerdp2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/freerdp2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/freerdp2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24882");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39320");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/freerdp2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the freerdp2-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24882");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-shadow-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-client2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-server2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-shadow-subsystem2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-shadow2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuwac0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuwac0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-tools2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winpr-utils");
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
    {'release': '11.0', 'prefix': 'freerdp2-dev', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'freerdp2-shadow-x11', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'freerdp2-wayland', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'freerdp2-x11', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libfreerdp-client2-2', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libfreerdp-server2-2', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libfreerdp-shadow-subsystem2-2', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libfreerdp-shadow2-2', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libfreerdp2-2', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libuwac0-0', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libuwac0-dev', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libwinpr-tools2-2', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libwinpr2-2', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'libwinpr2-dev', 'reference': '2.3.0+dfsg1-2+deb11u3'},
    {'release': '11.0', 'prefix': 'winpr-utils', 'reference': '2.3.0+dfsg1-2+deb11u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp2-dev / freerdp2-shadow-x11 / freerdp2-wayland / freerdp2-x11 / etc');
}
