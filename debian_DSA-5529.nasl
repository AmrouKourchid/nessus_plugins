#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5529. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(183306);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2023-41914");

  script_name(english:"Debian DSA-5529-1 : slurm-wlm - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5529
advisory.

    Francois Diakhate discovered that several race conditions in file processing of the Simple Linux Utility
    for Resource Management (SLURM), a cluster resource management and job scheduling system, could result in
    denial of service by overwriting arbitrary files. For the stable distribution (bookworm), this problem has
    been fixed in version 22.05.8-4+deb12u1. In addition slurm-wlm-contrib also needed to be patched in
    version 22.05.8-4+deb12u1. We recommend that you upgrade your slurm-wlm packages. For the detailed
    security status of slurm-wlm please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/slurm-wlm

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/slurm-wlm");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5529");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-41914");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/slurm-wlm");
  script_set_attribute(attribute:"solution", value:
"Upgrade the slurm-wlm packages.

For the stable distribution (bookworm), this problem has been fixed in version 22.05.8-4+deb12u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41914");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpam-slurm-adopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpmi2-0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurm-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurm38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libslurmdb-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-client-emulator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-basic-plugins-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-elasticsearch-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-elasticsearch-plugin-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-emulator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-hdf5-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-hdf5-plugin-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-influxdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-influxdb-plugin-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-ipmi-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-ipmi-plugins-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-jwt-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-jwt-plugin-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-mysql-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-mysql-plugin-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-plugins-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-rrd-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-rrd-plugin-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-rsmi-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-rsmi-plugin-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-wlm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmctld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurmrestd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sview");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'libpam-slurm', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libpam-slurm-adopt', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libpmi0', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libpmi0-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libpmi2-0', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libpmi2-0-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libslurm-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libslurm-perl', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libslurm38', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'libslurmdb-perl', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-client', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-client-emulator', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-basic-plugins', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-basic-plugins-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-doc', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-elasticsearch-plugin', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-elasticsearch-plugin-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-emulator', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-hdf5-plugin', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-hdf5-plugin-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-influxdb-plugin', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-influxdb-plugin-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-ipmi-plugins', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-ipmi-plugins-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-jwt-plugin', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-jwt-plugin-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-mysql-plugin', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-mysql-plugin-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-plugins', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-plugins-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-rrd-plugin', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-rrd-plugin-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-rsmi-plugin', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-rsmi-plugin-dev', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurm-wlm-torque', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurmctld', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurmd', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurmdbd', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'slurmrestd', 'reference': '22.05.8-4+deb12u1'},
    {'release': '12.0', 'prefix': 'sview', 'reference': '22.05.8-4+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpam-slurm / libpam-slurm-adopt / libpmi0 / libpmi0-dev / libpmi2-0 / etc');
}
