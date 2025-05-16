#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3904. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(207907);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id("CVE-2024-47175");

  script_name(english:"Debian dla-3904 : cups - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dla-3904
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3904-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                    Thorsten Alteholz
    September 29, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : cups
    Version        : 2.3.3op2-3+deb11u9
    CVE ID         : CVE-2024-47175


    Simone Margaritelli reported that cups, the Common UNIX Printing System,
    does not properly sanitize IPP attributes when creating PPD files, which
    may result in the execution of arbitrary code.


    For Debian 11 bullseye, this problem has been fixed in version
    2.3.3op2-3+deb11u9.

    We recommend that you upgrade your cups packages.

    For the detailed security status of cups please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/cups

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cups");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47175");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/cups");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47175");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS IPP Attributes LAN Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-core-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-ipp-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-ppdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcups2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsimage2-dev");
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
    {'release': '11.0', 'prefix': 'cups', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'cups-bsd', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'cups-client', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'cups-common', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'cups-core-drivers', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'cups-daemon', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'cups-ipp-utils', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'cups-ppdc', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'cups-server-common', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'libcups2', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'libcups2-dev', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'libcupsimage2', 'reference': '2.3.3op2-3+deb11u9'},
    {'release': '11.0', 'prefix': 'libcupsimage2-dev', 'reference': '2.3.3op2-3+deb11u9'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups / cups-bsd / cups-client / cups-common / cups-core-drivers / etc');
}
