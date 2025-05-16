#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5708. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(200366);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/11");

  script_cve_id("CVE-2024-34055");

  script_name(english:"Debian dsa-5708 : cyrus-admin - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5708
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5708-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    June 11, 2024                         https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : cyrus-imapd
    CVE ID         : CVE-2024-34055

    Damian Poddebniak discovered that the Cyrus IMAP server didn't restrict
    memory allocation for some command arguments which may result in denial
    of service. This update backports new config directives which allow to
    configure limits, additional details can be found at:

    https://www.cyrusimap.org/3.6/imap/download/release-notes/3.6/x/3.6.5.html

    These changes are too intrusive to be backported to the version of
    Cyrus in the oldstable distribution (bullseye). If the IMAP server is used
    by untrusted users an update to Debian stable/bookworm is recommended.
    In addition the version of cyrus-imapd in bullseye-backports will be
    updated with a patch soon.

    For the stable distribution (bookworm), this problem has been fixed in
    version 3.6.1-4+deb12u2.

    We recommend that you upgrade your cyrus-imapd packages.

    For the detailed security status of cyrus-imapd please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/cyrus-imapd

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cyrus-imapd");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-34055");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/cyrus-imapd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cyrus-admin packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34055");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-caldav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-nntpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-replication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcyrus-imap-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'cyrus-admin', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-caldav', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-clients', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-common', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-dev', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-doc', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-imapd', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-murder', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-nntpd', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-pop3d', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'cyrus-replication', 'reference': '3.6.1-4+deb12u2'},
    {'release': '12.0', 'prefix': 'libcyrus-imap-perl', 'reference': '3.6.1-4+deb12u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cyrus-admin / cyrus-caldav / cyrus-clients / cyrus-common / cyrus-dev / etc');
}
