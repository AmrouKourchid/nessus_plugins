#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3885-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122055);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6111");
  script_xref(name:"USN", value:"3885-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : OpenSSH vulnerabilities (USN-3885-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-3885-1 advisory.

    Harry Sintonen discovered multiple issues in the OpenSSH scp utility. If a user or automated system were
    tricked into connecting to an untrusted server, a remote attacker could possibly use these issues to write
    to arbitrary files, change directory permissions, and spoof client output.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3885-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6111");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6109");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client-ssh1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-server-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-sftp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'openssh-client', 'pkgver': '1:6.6p1-2ubuntu2.12'},
    {'osver': '14.04', 'pkgname': 'openssh-client-udeb', 'pkgver': '1:6.6p1-2ubuntu2.12'},
    {'osver': '14.04', 'pkgname': 'openssh-server', 'pkgver': '1:6.6p1-2ubuntu2.12'},
    {'osver': '14.04', 'pkgname': 'openssh-server-udeb', 'pkgver': '1:6.6p1-2ubuntu2.12'},
    {'osver': '14.04', 'pkgname': 'openssh-sftp-server', 'pkgver': '1:6.6p1-2ubuntu2.12'},
    {'osver': '14.04', 'pkgname': 'ssh', 'pkgver': '1:6.6p1-2ubuntu2.12'},
    {'osver': '14.04', 'pkgname': 'ssh-askpass-gnome', 'pkgver': '1:6.6p1-2ubuntu2.12'},
    {'osver': '14.04', 'pkgname': 'ssh-krb5', 'pkgver': '1:6.6p1-2ubuntu2.12'},
    {'osver': '16.04', 'pkgname': 'openssh-client', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'openssh-client-ssh1', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'openssh-client-udeb', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'openssh-server', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'openssh-server-udeb', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'openssh-sftp-server', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'ssh', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'ssh-askpass-gnome', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '16.04', 'pkgname': 'ssh-krb5', 'pkgver': '1:7.2p2-4ubuntu2.7'},
    {'osver': '18.04', 'pkgname': 'openssh-client', 'pkgver': '1:7.6p1-4ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'openssh-client-udeb', 'pkgver': '1:7.6p1-4ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'openssh-server', 'pkgver': '1:7.6p1-4ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'openssh-server-udeb', 'pkgver': '1:7.6p1-4ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'openssh-sftp-server', 'pkgver': '1:7.6p1-4ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'ssh', 'pkgver': '1:7.6p1-4ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'ssh-askpass-gnome', 'pkgver': '1:7.6p1-4ubuntu0.2'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssh-client / openssh-client-ssh1 / openssh-client-udeb / etc');
}
