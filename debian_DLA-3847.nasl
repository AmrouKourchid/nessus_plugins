#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3847. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(201127);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/28");

  script_cve_id(
    "CVE-2021-41687",
    "CVE-2021-41688",
    "CVE-2021-41689",
    "CVE-2021-41690",
    "CVE-2022-2121",
    "CVE-2022-43272",
    "CVE-2024-28130",
    "CVE-2024-34508",
    "CVE-2024-34509"
  );

  script_name(english:"Debian dla-3847 : dcmtk - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3847 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3847-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                          Adrian Bunk
    June 28, 2024                                 https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : dcmtk
    Version        : 3.6.4-2.1+deb10u1
    CVE ID         : CVE-2021-41687 CVE-2021-41688 CVE-2021-41689 CVE-2021-41690
                     CVE-2022-2121 CVE-2022-43272 CVE-2024-28130 CVE-2024-34508
                     CVE-2024-34509
    Debian Bug     : 1014044 1027165 1070207

    Multiple vulnerabilities havebenn fixed in DCMTK, a collection of
    libraries and applications implementing large parts the DICOM standard
    for medical images.

    CVE-2021-41687

        Incorrect freeing of memory

    CVE-2021-41688

        Incorrect freeing of memory

    CVE-2021-41689

        NULL pointer dereference

    CVE-2021-41690

        Incorrect freeing of memory

    CVE-2022-2121

        NULL pointer dereference

    CVE-2022-43272

        Memory leak in single process mode

    CVE-2024-28130

        Segmentation faults due to incorrect typecast

    CVE-2024-34508

        Segmentation fault via invalid DIMSE message

    CVE-2024-34509

        Segmentation fault via invalid DIMSE message

    For Debian 10 buster, these problems have been fixed in version
    3.6.4-2.1+deb10u1.

    We recommend that you upgrade your dcmtk packages.

    For the detailed security status of dcmtk please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/dcmtk

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dcmtk");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41687");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41688");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41689");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2121");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43272");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-28130");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-34508");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-34509");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/dcmtk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dcmtk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41690");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-28130");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dcmtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dcmtk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdcmtk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdcmtk14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'dcmtk', 'reference': '3.6.4-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'dcmtk-doc', 'reference': '3.6.4-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libdcmtk-dev', 'reference': '3.6.4-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libdcmtk14', 'reference': '3.6.4-2.1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dcmtk / dcmtk-doc / libdcmtk-dev / libdcmtk14');
}
