#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3522. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(179631);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2018-11206",
    "CVE-2018-17233",
    "CVE-2018-17234",
    "CVE-2018-17237",
    "CVE-2018-17434",
    "CVE-2018-17437"
  );

  script_name(english:"Debian dla-3522 : hdf5-helpers - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3522 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3522-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    August 09, 2023                               https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : hdf5
    Version        : 1.10.4+repack-10+deb10u1
    CVE ID         : CVE-2018-11206 CVE-2018-17233 CVE-2018-17234 CVE-2018-17237
                     CVE-2018-17434 CVE-2018-17437

    Multiple security vulnerabilities were discovered in HDF5, a Hierarchical
    Data Format and a library for scientific data. Memory leaks, out-of-bound
    reads and division by zero errors may lead to a denial of service when
    processing a malformed HDF file.

    For Debian 10 buster, these problems have been fixed in version
    1.10.4+repack-10+deb10u1.

    We recommend that you upgrade your hdf5 packages.

    For the detailed security status of hdf5 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/hdf5

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/hdf5");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-11206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-17233");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-17234");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-17237");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-17434");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-17437");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/hdf5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the hdf5-helpers packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11206");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hdf5-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hdf5-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-103");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-cpp-103");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-mpi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-mpich-103");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-mpich-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-openmpi-103");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdf5-openmpi-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'hdf5-helpers', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'hdf5-tools', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-103', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-cpp-103', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-dev', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-doc', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-java', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-jni', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-mpi-dev', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-mpich-103', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-mpich-dev', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-openmpi-103', 'reference': '1.10.4+repack-10+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdf5-openmpi-dev', 'reference': '1.10.4+repack-10+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hdf5-helpers / hdf5-tools / libhdf5-103 / libhdf5-cpp-103 / etc');
}
