#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3925. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(209341);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/03");

  script_cve_id("CVE-2024-42365", "CVE-2024-42491");

  script_name(english:"Debian dla-3925 : asterisk - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3925 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3925-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                    Thorsten Alteholz
    October 20, 2024                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : asterisk
    Version        : 1:16.28.0~dfsg-0+deb11u5
    CVE ID         : CVE-2024-42365 CVE-2024-42491


    Two issues have been found in asterisk, an Open Source Private Branch
    Exchange.


    CVE-2024-42365

        Due to a privilege escalation, remote code execution and/or
        blind server-side request forgery with arbitrary protocol are
        possible.

    CVE-2024-42491

        Due to bad handling of malformed Contact or Record-Route URI in an
        incoming  SIP request, Asterisk might crash when res_resolver_unbound
        is used.

    Thanks to Niels Galjaard, a minor privilege escalation has been fixed.
    More information about ths can be found at:

    https://alioth-lists.debian.net/pipermail/pkg-voip-maintainers/2024-July/038664.html


    For Debian 11 bullseye, these problems have been fixed in version
    1:16.28.0~dfsg-0+deb11u5.

    We recommend that you upgrade your asterisk packages.

    For the detailed security status of asterisk please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/asterisk

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/asterisk");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42365");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42491");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/asterisk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the asterisk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42365");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Asterisk AMI Originate Authenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dahdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-ooh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-imapstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-odbcstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-vpb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'asterisk', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-config', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-dahdi', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-dev', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-doc', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-mobile', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-modules', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-mp3', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-mysql', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-ooh323', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-tests', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-voicemail', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-voicemail-imapstorage', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-voicemail-odbcstorage', 'reference': '1:16.28.0~dfsg-0+deb11u5'},
    {'release': '11.0', 'prefix': 'asterisk-vpb', 'reference': '1:16.28.0~dfsg-0+deb11u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'asterisk / asterisk-config / asterisk-dahdi / asterisk-dev / etc');
}
