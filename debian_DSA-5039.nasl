#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5039. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156616);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2022-21661",
    "CVE-2022-21662",
    "CVE-2022-21663",
    "CVE-2022-21664"
  );
  script_xref(name:"IAVA", value:"2022-A-0003-S");

  script_name(english:"Debian DSA-5039-1 : wordpress - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5039 advisory.

    Several vulnerabilities were discovered in Wordpress, a web blogging tool. They allowed remote attackers
    to perform SQL injection, run unchecked SQL queries, bypass hardening, or perform Cross-Site Scripting
    (XSS) attacks. For the oldstable distribution (buster), these problems have been fixed in version
    5.0.15+dfsg1-0+deb10u1. For the stable distribution (bullseye), these problems have been fixed in version
    5.7.5+dfsg1-0+deb11u1. We recommend that you upgrade your wordpress packages. For the detailed security
    status of wordpress please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/wordpress

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1003243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5039");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21661");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21664");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wordpress");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wordpress packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.7.5+dfsg1-0+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21664");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentynineteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyseventeen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentysixteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentytwenty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentytwentyone");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'wordpress', 'reference': '5.0.15+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-l10n', 'reference': '5.0.15+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentynineteen', 'reference': '5.0.15+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentyseventeen', 'reference': '5.0.15+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentysixteen', 'reference': '5.0.15+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentytwenty', 'reference': '5.0.15+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentytwentyone', 'reference': '5.0.15+dfsg1-0+deb10u1'},
    {'release': '11.0', 'prefix': 'wordpress', 'reference': '5.7.5+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-l10n', 'reference': '5.7.5+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentynineteen', 'reference': '5.7.5+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentyseventeen', 'reference': '5.7.5+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentysixteen', 'reference': '5.7.5+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentytwenty', 'reference': '5.7.5+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentytwentyone', 'reference': '5.7.5+dfsg1-0+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'wordpress / wordpress-l10n / wordpress-theme-twentynineteen / etc');
}
