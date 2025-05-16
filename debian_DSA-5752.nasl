#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5752. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206014);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_cve_id("CVE-2024-23184", "CVE-2024-23185");
  script_xref(name:"IAVA", value:"2024-A-0504");

  script_name(english:"Debian dsa-5752 : dovecot-auth-lua - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5752 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5752-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    August 21, 2024                       https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : dovecot
    CVE ID         : CVE-2024-23184 CVE-2024-23185

    Two vulnerabilities have been discovered in the IMAP implementation of
    the Dovecot mail server: Excessive numbers of address headers or very
    large headers can result in high CPU usage, leading to denial of
    service.

    For the stable distribution (bookworm), these problems have been fixed in
    version 1:2.3.19.1+dfsg1-2.1+deb12u1.

    We recommend that you upgrade your dovecot packages.

    For the detailed security status of dovecot please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/dovecot

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dovecot");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-23185");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/dovecot");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dovecot-auth-lua packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23185");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-23184");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-auth-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lmtpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-managesieved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-submissiond");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'dovecot-auth-lua', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-core', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-dev', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-gssapi', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-imapd', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-ldap', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-lmtpd', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-lucene', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-managesieved', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-mysql', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-pgsql', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-pop3d', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-sieve', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-solr', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-sqlite', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'},
    {'release': '12.0', 'prefix': 'dovecot-submissiond', 'reference': '1:2.3.19.1+dfsg1-2.1+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dovecot-auth-lua / dovecot-core / dovecot-dev / dovecot-gssapi / etc');
}
