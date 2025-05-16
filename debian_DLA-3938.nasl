#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3938. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(209857);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id(
    "CVE-2021-38371",
    "CVE-2022-3559",
    "CVE-2023-42117",
    "CVE-2023-42119"
  );
  script_xref(name:"IAVA", value:"2022-A-0338-S");
  script_xref(name:"IAVA", value:"2023-A-0521-S");

  script_name(english:"Debian dla-3938 : exim4 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3938 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3938-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    October 29, 2024                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : exim4
    Version        : 4.94.2-7+deb11u4
    CVE ID         : CVE-2021-38371 CVE-2022-3559 CVE-2023-42117 CVE-2023-42119
    Debian Bug     : 992172

    Multiple potential security vulnerabilities have been addressed in exim4, a
    mail transport agent. These issues may allow remote attackers to disclose
    sensitive information or execute arbitrary code but only if Exim4 is run behind
    or with untrusted proxy servers or DNS resolvers. If your proxy-protocol proxy
    or DNS resolver are trustworthy, you are not affected.

    For Debian 11 bullseye, these problems have been fixed in version
    4.94.2-7+deb11u4.

    We recommend that you upgrade your exim4 packages.

    For the detailed security status of exim4 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/exim4

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/exim4");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38371");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3559");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42117");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-42119");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/exim4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the exim4 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38371");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eximon4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'exim4', 'reference': '4.94.2-7+deb11u4'},
    {'release': '11.0', 'prefix': 'exim4-base', 'reference': '4.94.2-7+deb11u4'},
    {'release': '11.0', 'prefix': 'exim4-config', 'reference': '4.94.2-7+deb11u4'},
    {'release': '11.0', 'prefix': 'exim4-daemon-heavy', 'reference': '4.94.2-7+deb11u4'},
    {'release': '11.0', 'prefix': 'exim4-daemon-light', 'reference': '4.94.2-7+deb11u4'},
    {'release': '11.0', 'prefix': 'exim4-dev', 'reference': '4.94.2-7+deb11u4'},
    {'release': '11.0', 'prefix': 'eximon4', 'reference': '4.94.2-7+deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exim4 / exim4-base / exim4-config / exim4-daemon-heavy / etc');
}
