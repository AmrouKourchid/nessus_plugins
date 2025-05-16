#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3585. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(181857);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-18651",
    "CVE-2020-18652",
    "CVE-2021-36045",
    "CVE-2021-36046",
    "CVE-2021-36047",
    "CVE-2021-36048",
    "CVE-2021-36050",
    "CVE-2021-36051",
    "CVE-2021-36052",
    "CVE-2021-36053",
    "CVE-2021-36054",
    "CVE-2021-36055",
    "CVE-2021-36056",
    "CVE-2021-36057",
    "CVE-2021-36058",
    "CVE-2021-36064",
    "CVE-2021-39847",
    "CVE-2021-40716",
    "CVE-2021-40732",
    "CVE-2021-42528",
    "CVE-2021-42529",
    "CVE-2021-42530",
    "CVE-2021-42531",
    "CVE-2021-42532"
  );

  script_name(english:"Debian dla-3585 : exempi - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3585 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3585-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    September 25, 2023                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : exempi
    Version        : 2.5.0-2+deb10u1
    CVE ID         : CVE-2020-18651 CVE-2020-18652 CVE-2021-36045 CVE-2021-36046
                     CVE-2021-36047 CVE-2021-36048 CVE-2021-36050 CVE-2021-36051
                     CVE-2021-36052 CVE-2021-36053 CVE-2021-36054 CVE-2021-36055
                     CVE-2021-36056 CVE-2021-36057 CVE-2021-36058 CVE-2021-36064
                     CVE-2021-39847 CVE-2021-40716 CVE-2021-40732 CVE-2021-42528
                     CVE-2021-42529 CVE-2021-42530 CVE-2021-42531 CVE-2021-42532

    Multiple vulneratibilities were found in exempi, an implementation of XMP
    (Extensible Metadata Platform).

    CVE-2020-18651

        A Buffer Overflow vulnerability was found
        in function ID3_Support::ID3v2Frame::getFrameValue
        allows remote attackers to cause a denial of service.

    CVE-2020-18652

        A Buffer Overflow vulnerability was found in
        WEBP_Support.cpp allows remote attackers to cause a
        denial of service.

    CVE-2021-36045

        An out-of-bounds read vulnerability was found
        that could lead to disclosure of arbitrary memory.

    CVE-2021-36046

        A memory corruption vulnerability was found,
        potentially resulting in arbitrary code execution
        in the context of the current use

    CVE-2021-36047

        An Improper Input Validation vulnerability was found,
        potentially resulting in arbitrary
        code execution in the context of the current use.

    CVE-2021-36048

        An Improper Input Validation was found,
        potentially resulting in arbitrary
        code execution in the context of the current user.

    CVE-2021-36050

        A buffer overflow vulnerability was found,
        potentially resulting in arbitrary code execution
        in the context of the current user.

    CVE-2021-36051

        A buffer overflow vulnerability was found,
        potentially resulting in arbitrary code execution
        in the context of the current user.

    CVE-2021-36052

        A memory corruption vulnerability was found,
        potentially resulting in arbitrary code execution
        in the context of the current user.

    CVE-2021-36053

        An out-of-bounds read vulnerability was found,
        that could lead to disclosure of arbitrary memory.

    CVE-2021-36054

        A buffer overflow vulnerability was found potentially
        resulting in local application denial of service.

    CVE-2021-36055

        A use-after-free vulnerability was found that could
        result in arbitrary code execution.

    CVE-2021-36056

        A buffer overflow vulnerability was found, potentially
        resulting in arbitrary code execution in the context of
        the current user.

    CVE-2021-36057

         A write-what-where condition vulnerability was found,
         caused during the application's memory allocation process.
         This may cause the memory management functions to become
         mismatched resulting in local application denial of service
         in the context of the current user.

    CVE-2021-36058

        An Integer Overflow vulnerability was found, potentially
        resulting in application-level denial of service in the
        context of the current user.

    CVE-2021-36064

        A Buffer Underflow vulnerability was found which
        could result in arbitrary code execution in the context
        of the current user

    CVE-2021-39847

        A stack-based buffer overflow vulnerability
        potentially resulting in arbitrary code execution in the
        context of the current user.

    CVE-2021-40716

        An out-of-bounds read vulnerability was found that
        could lead to disclosure of sensitive memory

    CVE-2021-40732

        A null pointer dereference vulnerability was found,
        that could result in leaking data from certain memory
        locations and causing a local denial of service

    CVE-2021-42528

        A Null pointer dereference vulnerability was found
        when parsing a specially crafted file. An unauthenticated attacker
        could leverage this vulnerability to achieve an application
        denial-of-service in the context of the current user.

    CVE-2021-42529

        A stack-based buffer overflow vulnerability was found
        potentially resulting in arbitrary code execution
        in the context of the current user.

    CVE-2021-42530

        A stack-based buffer overflow vulnerability was found
        potentially resulting in arbitrary code execution in the
        context of the current user.

    CVE-2021-42531

        A stack-based buffer overflow vulnerability
        potentially resulting in arbitrary code execution in
        the context of the current user

    CVE-2021-42532

        A stack-based buffer overflow vulnerability
        potentially resulting in arbitrary code execution in the
        context of the current user.

    For Debian 10 buster, these problems have been fixed in version
    2.5.0-2+deb10u1.

    We recommend that you upgrade your exempi packages.

    For the detailed security status of exempi please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/exempi

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/exempi");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-18651");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-18652");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36045");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36046");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36047");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36048");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36050");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36051");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36052");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36053");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36054");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36055");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36056");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36057");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36064");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39847");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40716");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40732");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42528");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42529");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42530");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42531");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42532");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/exempi");
  script_set_attribute(attribute:"solution", value:
"Upgrade the exempi packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42532");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exempi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexempi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexempi8");
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
    {'release': '10.0', 'prefix': 'exempi', 'reference': '2.5.0-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libexempi-dev', 'reference': '2.5.0-2+deb10u1'},
    {'release': '10.0', 'prefix': 'libexempi8', 'reference': '2.5.0-2+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exempi / libexempi-dev / libexempi8');
}
