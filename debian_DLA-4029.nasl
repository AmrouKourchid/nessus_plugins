#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4029. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(214524);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id("CVE-2024-55553");

  script_name(english:"Debian dla-4029 : frr - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dla-4029
advisory.

    -lts-announce@lists.debian.org
    Subject: [SECURITY] [DLA 4029-1] frr security update

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4029-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/              Arturo Borrero Gonzalez
    January 23, 2025                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : frr
    Version        : 7.5.1-1.1+deb11u4
    CVE ID         : CVE-2024-55553

    In FRR, the internet routing protocol suite software, all routes are
    re-validated if the total size of an update received via RTR exceeds the
    internal socket's buffer size, default 4K on most OSes.

    An attacker can use this to trigger re-parsing of the RIB for FRR routers
    using RTR by causing more than this number of updates during an update
    interval (usually 30 minutes). Additionally, this effect regularly occurs
    organically. Furthermore, an attacker can use this to trigger route validation
    continuously. Given that routers with large full tables may need more than
    30 minutes to fully re-validate the table, continuous issuance/withdrawal of
    large numbers of ROA may be used to impact the route handling performance of
    all FRR instances using RPKI globally. Additionally, the re-validation will
    cause heightened BMP traffic to ingestors.

    For Debian 11 bullseye, this problem has been fixed in version
    7.5.1-1.1+deb11u4.

    We recommend that you upgrade your frr packages.

    For the detailed security status of frr please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/frr

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/frr");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-55553");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/frr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the frr packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-55553");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-pythontools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-rpki-rtrlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:frr-snmp");
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
    {'release': '11.0', 'prefix': 'frr', 'reference': '7.5.1-1.1+deb11u4'},
    {'release': '11.0', 'prefix': 'frr-doc', 'reference': '7.5.1-1.1+deb11u4'},
    {'release': '11.0', 'prefix': 'frr-pythontools', 'reference': '7.5.1-1.1+deb11u4'},
    {'release': '11.0', 'prefix': 'frr-rpki-rtrlib', 'reference': '7.5.1-1.1+deb11u4'},
    {'release': '11.0', 'prefix': 'frr-snmp', 'reference': '7.5.1-1.1+deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'frr / frr-doc / frr-pythontools / frr-rpki-rtrlib / frr-snmp');
}
