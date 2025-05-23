#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5586. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(187213);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2021-41617",
    "CVE-2023-28531",
    "CVE-2023-48795",
    "CVE-2023-51384",
    "CVE-2023-51385"
  );
  script_xref(name:"IAVA", value:"2021-A-0474-S");
  script_xref(name:"IAVA", value:"2023-A-0152-S");
  script_xref(name:"IAVA", value:"2023-A-0703");
  script_xref(name:"IAVA", value:"2023-A-0701-S");

  script_name(english:"Debian DSA-5586-1 : openssh - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5586 advisory.

    Several vulnerabilities have been discovered in OpenSSH, an implementation of the SSH protocol suite.
    CVE-2021-41617 It was discovered that sshd failed to correctly initialise supplemental groups when
    executing an AuthorizedKeysCommand or AuthorizedPrincipalsCommand, where a AuthorizedKeysCommandUser or
    AuthorizedPrincipalsCommandUser directive has been set to run the command as a different user. Instead
    these commands would inherit the groups that sshd was started with. CVE-2023-28531 Luci Stanescu reported
    that a error prevented constraints being communicated to the ssh-agent when adding smartcard keys to the
    agent with per-hop destination constraints, resulting in keys being added without constraints.
    CVE-2023-48795 Fabian Baeumer, Marcus Brinkmann and Joerg Schwenk discovered that the SSH protocol is
    prone to a prefix truncation attack, known as the Terrapin attack. This attack allows a MITM attacker to
    effect a limited break of the integrity of the early encrypted SSH transport protocol by sending extra
    messages prior to the commencement of encryption, and deleting an equal number of consecutive messages
    immediately after encryption starts. Details can be found at https://terrapin-attack.com/ CVE-2023-51384
    It was discovered that when PKCS#11-hosted private keys were added while specifying destination
    constraints, if the PKCS#11 token returned multiple keys then only the first key had the constraints
    applied. CVE-2023-51385 It was discovered that if an invalid user or hostname that contained shell
    metacharacters was passed to ssh, and a ProxyCommand, LocalCommand directive or match exec predicate
    referenced the user or hostname via expansion tokens, then an attacker who could supply arbitrary
    user/hostnames to ssh could potentially perform command injection. The situation could arise in case of
    git repositories with submodules, where the repository could contain a submodule with shell characters in
    its user or hostname. For the oldstable distribution (bullseye), these problems have been fixed in version
    1:8.4p1-5+deb11u3. For the stable distribution (bookworm), these problems have been fixed in version
    1:9.2p1-2+deb12u2. We recommend that you upgrade your openssh packages. For the detailed security status
    of openssh please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/openssh

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=995130");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/openssh");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openssh");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41617");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-28531");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-48795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-51384");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-51385");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/openssh");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openssh packages.

For the stable distribution (bookworm), these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28531");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-server-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-sftp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'openssh-client', 'reference': '1:8.4p1-5+deb11u3'},
    {'release': '11.0', 'prefix': 'openssh-client-udeb', 'reference': '1:8.4p1-5+deb11u3'},
    {'release': '11.0', 'prefix': 'openssh-server', 'reference': '1:8.4p1-5+deb11u3'},
    {'release': '11.0', 'prefix': 'openssh-server-udeb', 'reference': '1:8.4p1-5+deb11u3'},
    {'release': '11.0', 'prefix': 'openssh-sftp-server', 'reference': '1:8.4p1-5+deb11u3'},
    {'release': '11.0', 'prefix': 'openssh-tests', 'reference': '1:8.4p1-5+deb11u3'},
    {'release': '11.0', 'prefix': 'ssh', 'reference': '1:8.4p1-5+deb11u3'},
    {'release': '11.0', 'prefix': 'ssh-askpass-gnome', 'reference': '1:8.4p1-5+deb11u3'},
    {'release': '12.0', 'prefix': 'openssh-client', 'reference': '1:9.2p1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'openssh-client-udeb', 'reference': '1:9.2p1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'openssh-server', 'reference': '1:9.2p1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'openssh-server-udeb', 'reference': '1:9.2p1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'openssh-sftp-server', 'reference': '1:9.2p1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'openssh-tests', 'reference': '1:9.2p1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'ssh', 'reference': '1:9.2p1-2+deb12u2'},
    {'release': '12.0', 'prefix': 'ssh-askpass-gnome', 'reference': '1:9.2p1-2+deb12u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssh-client / openssh-client-udeb / openssh-server / etc');
}
