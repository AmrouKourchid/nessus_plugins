#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5881. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(232892);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2023-28362",
    "CVE-2023-38037",
    "CVE-2024-26144",
    "CVE-2024-28103",
    "CVE-2024-41128",
    "CVE-2024-47887",
    "CVE-2024-47888",
    "CVE-2024-47889",
    "CVE-2024-54133"
  );

  script_name(english:"Debian dsa-5881 : rails - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5881 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5881-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    March 17, 2025                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : rails
    CVE ID         : CVE-2023-28362 CVE-2023-38037 CVE-2024-26144 CVE-2024-28103
                     CVE-2024-41128 CVE-2024-47887 CVE-2024-47888 CVE-2024-47889
                     CVE-2024-54133

    Multiple security issues were discovered in the Rails web framework
    which could result cross-site scripting, information disclosure, denial
    of service or bypass of content security policies.

    For the stable distribution (bookworm), these problems have been fixed in
    version 2:6.1.7.10+dfsg-1~deb12u1.

    We recommend that you upgrade your rails packages.

    For the detailed security status of rails please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/rails

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/rails");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28362");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-28103");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-41128");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47887");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47888");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-54133");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/rails");
  script_set_attribute(attribute:"solution", value:
"Upgrade the rails packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28103");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-47889");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionmailbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actiontext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-railties");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'rails', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-actioncable', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-actionmailbox', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-actionmailer', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-actionpack', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-actiontext', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-actionview', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-activejob', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-activemodel', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-activerecord', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-activestorage', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-activesupport', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-rails', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'},
    {'release': '12.0', 'prefix': 'ruby-railties', 'reference': '2:6.1.7.10+dfsg-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rails / ruby-actioncable / ruby-actionmailbox / ruby-actionmailer / etc');
}
