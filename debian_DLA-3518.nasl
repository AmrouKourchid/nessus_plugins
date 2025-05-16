#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3518. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(179425);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2022-41649",
    "CVE-2022-41684",
    "CVE-2022-41794",
    "CVE-2022-41837",
    "CVE-2023-24472",
    "CVE-2023-36183"
  );

  script_name(english:"Debian dla-3518 : libopenimageio-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3518 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3518-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    August 07, 2023                               https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : openimageio
    Version        : 2.0.5~dfsg0-1+deb10u2
    CVE ID         : CVE-2022-41649 CVE-2022-41684 CVE-2022-41794 CVE-2022-41837
                     CVE-2023-24472 CVE-2023-36183
    Debian Bug     : 1027143 1034151

    Multiple security vulnerabilities have been discovered in OpenImageIO, a
    library for reading and writing images. Buffer overflows and out-of-bounds
    read and write programming errors may lead to a denial of service
    (application crash) or the execution of arbitrary code if a malformed image
    file is processed.

    For Debian 10 buster, these problems have been fixed in version
    2.0.5~dfsg0-1+deb10u2.

    We recommend that you upgrade your openimageio packages.

    For the detailed security status of openimageio please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/openimageio

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openimageio");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41649");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41684");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41794");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41837");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24472");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-36183");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/openimageio");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libopenimageio-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41837");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenimageio-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenimageio-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenimageio2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openimageio-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-openimageio");
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
    {'release': '10.0', 'prefix': 'libopenimageio-dev', 'reference': '2.0.5~dfsg0-1+deb10u2'},
    {'release': '10.0', 'prefix': 'libopenimageio-doc', 'reference': '2.0.5~dfsg0-1+deb10u2'},
    {'release': '10.0', 'prefix': 'libopenimageio2.0', 'reference': '2.0.5~dfsg0-1+deb10u2'},
    {'release': '10.0', 'prefix': 'openimageio-tools', 'reference': '2.0.5~dfsg0-1+deb10u2'},
    {'release': '10.0', 'prefix': 'python3-openimageio', 'reference': '2.0.5~dfsg0-1+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenimageio-dev / libopenimageio-doc / libopenimageio2.0 / etc');
}
