#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3462. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177458);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id("CVE-2023-2745");

  script_name(english:"Debian dla-3462 : wordpress - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3462
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3462-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    June 21, 2023                                 https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : wordpress
    Version        : 5.0.19+dfsg1-0+deb10u1
    CVE ID         : CVE-2023-2745
    Debian Bug     : 1036296

    Several security vulnerabilities have been addressed in Wordpress, a
    popular content management framework.

    WordPress Core is vulnerable to Directory Traversal via the wp_lang
    parameter. This allows unauthenticated attackers to access and load arbitrary
    translation files. In cases where an attacker is able to upload a crafted
    translation file onto the site, such as via an upload form, this could be also
    used to perform a Cross-Site Scripting attack.

    For Debian 10 buster, this problem has been fixed in version
    5.0.19+dfsg1-0+deb10u1.

    We recommend that you upgrade your wordpress packages.

    For the detailed security status of wordpress please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/wordpress

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2745");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/wordpress");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wordpress packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2745");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentynineteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyseventeen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentysixteen");
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
    {'release': '10.0', 'prefix': 'wordpress', 'reference': '5.0.19+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-l10n', 'reference': '5.0.19+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentynineteen', 'reference': '5.0.19+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentyseventeen', 'reference': '5.0.19+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentysixteen', 'reference': '5.0.19+dfsg1-0+deb10u1'}
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
