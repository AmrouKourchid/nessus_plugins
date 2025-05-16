#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4160. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(235667);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2017-14227",
    "CVE-2018-16790",
    "CVE-2023-0437",
    "CVE-2024-6381",
    "CVE-2024-6383",
    "CVE-2025-0755"
  );

  script_name(english:"Debian dla-4160 : libbson-xs-perl - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-4160 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4160-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                  Roberto C. Snchez
    May 09, 2025                                  https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : libbson-xs-perl
    Version        : 0.8.4-1+deb11u1
    CVE ID         : CVE-2017-14227 CVE-2018-16790 CVE-2023-0437 CVE-2024-6381
                     CVE-2024-6383 CVE-2025-0755

    Several vulnerabilities have been found in libbson-xs-perl, the Perl XS
    implementation of MongoDB's BSON serialization.

    CVE-2017-14227

        The bson_iter_codewscope function in bson-iter.c miscalculates a
        bson_utf8_validate length argument, which allows remote attackers to
        cause a denial of service (heap-based buffer over-read in the
        bson_utf8_validate function in bson-utf8.c), as demonstrated by
        bson-to-json.c.

    CVE-2018-16790

        _bson_iter_next_internal has a heap-based buffer over-read via a
        crafted bson buffer.

    CVE-2023-0437

        When calling bson_utf8_validate on some inputs a loop with an exit
        condition that cannot be reached may occur, i.e. an infinite loop.

    CVE-2024-6381

        The bson_strfreev function in the MongoDB C driver library may be
        susceptible to an integer overflow where the function will try to
        free memory at a negative offset. This may result in memory
        corruption.

    CVE-2024-6383

        The bson_string_append function in MongoDB C Driver may be
        vulnerable to a buffer overflow where the function might attempt to
        allocate too small of buffer and may lead to memory corruption of
        neighbouring heap memory.

    CVE-2025-0755

        The various bson_append functions in the MongoDB C driver library
        may be susceptible to buffer overflow when performing operations
        that could result in a final BSON document which exceeds the maximum
        allowable size (INT32_MAX), resulting in a segmentation fault and
        possible application crash.

    For Debian 11 bullseye, these problems have been fixed in version
    0.8.4-1+deb11u1.

    We recommend that you upgrade your libbson-xs-perl packages.

    For the detailed security status of libbson-xs-perl please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libbson-xs-perl

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/libbson-xs-perl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d5810d7");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-14227");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-16790");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0437");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-6381");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-6383");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-0755");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libbson-xs-perl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libbson-xs-perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbson-xs-perl");
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
    {'release': '11.0', 'prefix': 'libbson-xs-perl', 'reference': '0.8.4-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libbson-xs-perl');
}
