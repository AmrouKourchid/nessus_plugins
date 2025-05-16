#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5685. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(195202);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2023-2745",
    "CVE-2023-5561",
    "CVE-2023-38000",
    "CVE-2023-39999",
    "CVE-2024-31210"
  );
  script_xref(name:"IAVA", value:"2023-A-0567-S");
  script_xref(name:"IAVA", value:"2024-A-0450-S");

  script_name(english:"Debian dsa-5685 : wordpress - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5685 advisory.

  - WordPress Core is vulnerable to Directory Traversal in versions up to, and including, 6.2, via the
    wp_lang' parameter. This allows unauthenticated attackers to access and load arbitrary translation files.
    In cases where an attacker is able to upload a crafted translation file onto the site, such as via an
    upload form, this could be also used to perform a Cross-Site Scripting attack. (CVE-2023-2745)

  - Auth. Stored (contributor+) Cross-Site Scripting (XSS) vulnerability in WordPress core 6.3 through 6.3.1,
    from 6.2 through 6.2.2, from 6.1 through 6.1.3, from 6.0 through 6.0.5, from 5.9 through 5.9.7 and
    Gutenberg plugin <= 16.8.0 versions. (CVE-2023-38000)

  - Exposure of Sensitive Information to an Unauthorized Actor in WordPress from 6.3 through 6.3.1, from 6.2
    through 6.2.2, from 6.1 through 6.13, from 6.0 through 6.0.5, from 5.9 through 5.9.7, from 5.8 through
    5.8.7, from 5.7 through 5.7.9, from 5.6 through 5.6.11, from 5.5 through 5.5.12, from 5.4 through 5.4.13,
    from 5.3 through 5.3.15, from 5.2 through 5.2.18, from 5.1 through 5.1.16, from 5.0 through 5.0.19, from
    4.9 through 4.9.23, from 4.8 through 4.8.22, from 4.7 through 4.7.26, from 4.6 through 4.6.26, from 4.5
    through 4.5.29, from 4.4 through 4.4.30, from 4.3 through 4.3.31, from 4.2 through 4.2.35, from 4.1
    through 4.1.38. (CVE-2023-39999)

  - WordPress does not properly restrict which user fields are searchable via the REST API, allowing
    unauthenticated attackers to discern the email addresses of users who have published public posts on an
    affected website via an Oracle style attack (CVE-2023-5561)

  - WordPress is an open publishing platform for the Web. It's possible for a file of a type other than a zip
    file to be submitted as a new plugin by an administrative user on the Plugins -> Add New -> Upload Plugin
    screen in WordPress. If FTP credentials are requested for installation (in order to move the file into
    place outside of the `uploads` directory) then the uploaded file remains temporary available in the Media
    Library despite it not being allowed. If the `DISALLOW_FILE_EDIT` constant is set to `true` on the site
    _and_ FTP credentials are required when uploading a new theme or plugin, then this technically allows an
    RCE when the user would otherwise have no means of executing arbitrary PHP code. This issue _only_ affects
    Administrator level users on single site installations, and Super Admin level users on Multisite
    installations where it's otherwise expected that the user does not have permission to upload or execute
    arbitrary PHP code. Lower level users are not affected. Sites where the `DISALLOW_FILE_MODS` constant is
    set to `true` are not affected. Sites where an administrative user either does not need to enter FTP
    credentials or they have access to the valid FTP credentials, are not affected. The issue was fixed in
    WordPress 6.4.3 on January 30, 2024 and backported to versions 6.3.3, 6.2.4, 6.1.5, 6.0.7, 5.9.9, 5.8.9,
    5.7.11, 5.6.13, 5.5.14, 5.4.15, 5.3.17, 5.2.20, 5.1.18, 5.0.21, 4.9.25, 2.8.24, 4.7.28, 4.6.28, 4.5.31,
    4.4.32, 4.3.33, 4.2.37, and 4.1.40. A workaround is available. If the `DISALLOW_FILE_MODS` constant is
    defined as `true` then it will not be possible for any user to upload a plugin and therefore this issue
    will not be exploitable. (CVE-2024-31210)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38000");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39999");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-5561");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31210");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wordpress");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wordpress packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38000");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentynineteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentytwenty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentytwentyone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentytwentythree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentytwentytwo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'wordpress', 'reference': '5.7.11+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-l10n', 'reference': '5.7.11+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentynineteen', 'reference': '5.7.11+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentytwenty', 'reference': '5.7.11+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentytwentyone', 'reference': '5.7.11+dfsg1-0+deb11u1'},
    {'release': '12.0', 'prefix': 'wordpress', 'reference': '6.1.6+dfsg1-0+deb12u1'},
    {'release': '12.0', 'prefix': 'wordpress-l10n', 'reference': '6.1.6+dfsg1-0+deb12u1'},
    {'release': '12.0', 'prefix': 'wordpress-theme-twentytwentyone', 'reference': '6.1.6+dfsg1-0+deb12u1'},
    {'release': '12.0', 'prefix': 'wordpress-theme-twentytwentythree', 'reference': '6.1.6+dfsg1-0+deb12u1'},
    {'release': '12.0', 'prefix': 'wordpress-theme-twentytwentytwo', 'reference': '6.1.6+dfsg1-0+deb12u1'}
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
