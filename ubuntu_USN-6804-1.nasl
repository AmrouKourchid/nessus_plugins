#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6804-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198244);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id(
    "CVE-2024-33599",
    "CVE-2024-33600",
    "CVE-2024-33601",
    "CVE-2024-33602"
  );
  script_xref(name:"USN", value:"6804-1");
  script_xref(name:"IAVA", value:"2025-A-0062");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS : GNU C Library vulnerabilities (USN-6804-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-6804-1 advisory.

    It was discovered that GNU C Library nscd daemon contained a stack-based buffer overflow. A local attacker
    could use this to cause a denial of service (system crash). (CVE-2024-33599)

    It was discovered that GNU C Library nscd daemon did not properly check the cache content, leading to a
    null pointer dereference vulnerability. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2024-33600)

    It was discovered that GNU C Library nscd daemon did not properly validate memory allocation in certain
    situations, leading to a null pointer dereference vulnerability. A local attacker could use this to cause
    a denial of service (system crash). (CVE-2024-33601)

    It was discovered that GNU C Library nscd daemon did not properly handle memory allocation, which could
    lead to memory corruption. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2024-33602)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6804-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-33599");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:glibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc-devtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-dev-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-lse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libc6-x32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multiarch-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nscd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 23.10 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'glibc-source', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc-bin', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-armel', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-dev', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-i386', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-pic', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-s390', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libc6-x32', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'locales', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'locales-all', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'multiarch-support', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nscd', 'pkgver': '2.23-0ubuntu11.3+esm7', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'glibc-source', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc-bin', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-armel', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-dev', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-i386', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-lse', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-pic', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-s390', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libc6-x32', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'locales', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'locales-all', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'multiarch-support', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'nscd', 'pkgver': '2.27-3ubuntu1.6+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'glibc-source', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc-bin', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-armel', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-dev', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-dev-armel', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-i386', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-lse', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-pic', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-prof', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-s390', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libc6-x32', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'locales', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'locales-all', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nscd', 'pkgver': '2.31-0ubuntu9.16', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'glibc-source', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc-bin', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc-devtools', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-dev', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-i386', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-prof', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-s390', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libc6-x32', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'locales', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'locales-all', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'nscd', 'pkgver': '2.35-0ubuntu3.8', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'glibc-source', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc-bin', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc-dev-bin', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc-devtools', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-amd64', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-dev', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-i386', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-prof', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-s390', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libc6-x32', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'locales', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'locales-all', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'nscd', 'pkgver': '2.38-1ubuntu6.3', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'glibc-source', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc-bin', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc-dev-bin', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc-devtools', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-amd64', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-dev', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-dev-amd64', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-dev-i386', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-dev-s390', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-dev-x32', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-i386', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-s390', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'libc6-x32', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'locales', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'locales-all', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE},
    {'osver': '24.04', 'pkgname': 'nscd', 'pkgver': '2.39-0ubuntu8.2', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc-source / libc-bin / libc-dev-bin / libc-devtools / libc6 / etc');
}
