#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3893. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(207413);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2023-52425",
    "CVE-2024-45490",
    "CVE-2024-45491",
    "CVE-2024-45492"
  );
  script_xref(name:"IAVA", value:"2024-A-0134-S");
  script_xref(name:"IAVA", value:"2024-A-0543-S");

  script_name(english:"Debian dla-3893 : expat - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3893 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3893-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    September 19, 2024                            https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : expat
    Version        : 2.2.10-2+deb11u6
    CVE ID         : CVE-2023-52425 CVE-2024-45490 CVE-2024-45491 CVE-2024-45492
    Debian Bug     : 1063238 1080149 1080150 1080152

    Multiple vulnerabilities were found in expat, an XML parsing C library,
    which could lead to Denial of Service, memory corruption or arbitrary
    code execution.

    CVE-2023-52425

        Snild Dolkow discovered that when parsing a large token that
        requires multiple buffer fills to complete, expat has to re-parse
        the token from start multiple times, which could lead to Denial of
        Service via resource exhaustion.

    CVE-2024-45490

        TaiYou discovered that xmlparse.c does not reject a negative length
        for XML_ParseBuffer(), which may cause memory corruption or code
        execution.

    CVE-2024-45491

        TaiYou discovered that xmlparse.c has an integer overflow for
        `nDefaultAtts` on 32-bit platforms, which may cause denial of
        service or code execution.

    CVE-2024-45492

        TaiYou discovered that xmlparse.c has an integer overflow for
        `m_groupSize` on 32-bit platforms, which may cause denial of service
        or code execution.

    For Debian 11 bullseye, these problems have been fixed in version
    2.2.10-2+deb11u6.

    We recommend that you upgrade your expat packages.

    For the detailed security status of expat please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/expat

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/expat");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-52425");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45490");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45491");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45492");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/expat");
  script_set_attribute(attribute:"solution", value:
"Upgrade the expat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexpat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexpat1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexpat1-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'expat', 'reference': '2.2.10-2+deb11u6'},
    {'release': '11.0', 'prefix': 'libexpat1', 'reference': '2.2.10-2+deb11u6'},
    {'release': '11.0', 'prefix': 'libexpat1-dev', 'reference': '2.2.10-2+deb11u6'},
    {'release': '11.0', 'prefix': 'libexpat1-udeb', 'reference': '2.2.10-2+deb11u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'expat / libexpat1 / libexpat1-dev / libexpat1-udeb');
}
