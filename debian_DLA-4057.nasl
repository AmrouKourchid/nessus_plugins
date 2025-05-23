#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4057. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(216406);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2025-26465");
  script_xref(name:"IAVA", value:"2025-A-0126-S");

  script_name(english:"Debian dla-4057 : openssh-client - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dla-4057
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4057-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Colin Watson
    February 18, 2025                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : openssh
    Version        : 1:8.4p1-5+deb11u4
    CVE ID         : CVE-2025-26465

    The Qualys Threat Research Unit (TRU) discovered that the OpenSSH client
    is vulnerable to a machine-in-the-middle attack if the VerifyHostKeyDNS
    option is enabled (disabled by default).

    Details can be found in the Qualys advisory at
    https://www.qualys.com/2025/02/18/openssh-mitm-dos.txt

    For Debian 11 bullseye, this problem has been fixed in version
    1:8.4p1-5+deb11u4.

    We recommend that you upgrade your openssh packages.

    For the detailed security status of openssh please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/openssh

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openssh");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-26465");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/openssh");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openssh-client packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-server-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-sftp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '11.0', 'prefix': 'openssh-client', 'reference': '1:8.4p1-5+deb11u4'},
    {'release': '11.0', 'prefix': 'openssh-client-udeb', 'reference': '1:8.4p1-5+deb11u4'},
    {'release': '11.0', 'prefix': 'openssh-server', 'reference': '1:8.4p1-5+deb11u4'},
    {'release': '11.0', 'prefix': 'openssh-server-udeb', 'reference': '1:8.4p1-5+deb11u4'},
    {'release': '11.0', 'prefix': 'openssh-sftp-server', 'reference': '1:8.4p1-5+deb11u4'},
    {'release': '11.0', 'prefix': 'openssh-tests', 'reference': '1:8.4p1-5+deb11u4'},
    {'release': '11.0', 'prefix': 'ssh', 'reference': '1:8.4p1-5+deb11u4'},
    {'release': '11.0', 'prefix': 'ssh-askpass-gnome', 'reference': '1:8.4p1-5+deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssh-client / openssh-client-udeb / openssh-server / etc');
}
