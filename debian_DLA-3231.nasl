#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3231. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168488);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2020-29394", "CVE-2020-36244", "CVE-2022-31291");

  script_name(english:"Debian dla-3231 : dlt-daemon - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3231 advisory.

    - -----------------------------------------------------------------------
    Debian LTS Advisory DLA-3231-1              debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Utkarsh Gupta
    December 07, 2022                           https://wiki.debian.org/LTS
    - -----------------------------------------------------------------------

    Package        : dlt-daemon
    Version        : 2.18.0-1+deb10u1
    CVE ID         : CVE-2020-29394 CVE-2020-36244 CVE-2022-31291
    Debian Bug     : 976228 1014534

    dlt-daemon, a Diagnostic Log and Trace logging daemon, had the following
    vulnerabilities reported:

    CVE-2020-29394

        A buffer overflow in the dlt_filter_load function in dlt_common.c
        from dlt-daemon allows arbitrary code execution because fscanf is
        misused (no limit on the number of characters to be read in the
        format argument).

    CVE-2020-36244

        dlt-daemon was vulnerable to a heap-based buffer overflow that
        could allow an attacker to remotely execute arbitrary code.

    CVE-2022-31291

        An issue in dlt_config_file_parser.c of dlt-daemon allows attackers
        to cause a double free via crafted TCP packets.

    For Debian 10 buster, these problems have been fixed in version
    2.18.0-1+deb10u1.

    We recommend that you upgrade your dlt-daemon packages.

    For the detailed security status of dlt-daemon please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/dlt-daemon

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dlt-daemon");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-29394");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31291");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/dlt-daemon");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dlt-daemon packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36244");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dlt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dlt-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdlt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdlt-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdlt2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'release': '10.0', 'prefix': 'dlt-daemon', 'reference': '2.18.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'dlt-tools', 'reference': '2.18.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libdlt-dev', 'reference': '2.18.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libdlt-examples', 'reference': '2.18.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'libdlt2', 'reference': '2.18.0-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dlt-daemon / dlt-tools / libdlt-dev / libdlt-examples / libdlt2');
}
