#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3120. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165449);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2018-18897",
    "CVE-2018-19058",
    "CVE-2018-20650",
    "CVE-2019-9903",
    "CVE-2019-9959",
    "CVE-2019-14494",
    "CVE-2020-27778",
    "CVE-2022-27337",
    "CVE-2022-38784"
  );
  script_xref(name:"IAVB", value:"2022-B-0039-S");
  script_xref(name:"IAVB", value:"2022-B-0050-S");

  script_name(english:"Debian dla-3120 : gir1.2-poppler-0.18 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3120 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3120-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    September 26, 2022                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : poppler
    Version        : 0.71.0-5+deb10u1
    CVE ID         : CVE-2018-18897 CVE-2018-19058 CVE-2018-20650 CVE-2019-9903
                     CVE-2019-9959 CVE-2019-14494 CVE-2020-27778 CVE-2022-27337
                     CVE-2022-38784
    Debian Bug     : 913164 913177 917974 925264 941776 933812 1010695 1018971

    Several security vulnerabilities have been discovered in Poppler, a PDF
    rendering library, that could lead to denial of service or possibly other
    unspecified impact when processing maliciously crafted documents.

    For Debian 10 buster, these problems have been fixed in version
    0.71.0-5+deb10u1.

    We recommend that you upgrade your poppler packages.

    For the detailed security status of poppler please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/poppler

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/poppler");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18897");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-19058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20650");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14494");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-9903");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-9959");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27778");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27337");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38784");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/poppler");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gir1.2-poppler-0.18 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27778");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-38784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-poppler-0.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp0v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt5-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler82");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'gir1.2-poppler-0.18', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-cpp-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-cpp0v5', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-glib-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-glib-doc', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-glib8', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-private-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-qt5-1', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler-qt5-dev', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'libpoppler82', 'reference': '0.71.0-5+deb10u1'},
    {'release': '10.0', 'prefix': 'poppler-utils', 'reference': '0.71.0-5+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gir1.2-poppler-0.18 / libpoppler-cpp-dev / libpoppler-cpp0v5 / etc');
}
