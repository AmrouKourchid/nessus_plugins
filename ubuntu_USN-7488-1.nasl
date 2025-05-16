#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7488-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235360);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id("CVE-2024-6232", "CVE-2024-9287", "CVE-2024-11168");
  script_xref(name:"USN", value:"7488-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.10 : Python vulnerabilities (USN-7488-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.10 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-7488-1 advisory.

    It was discovered that Python incorrectly handled parsing bracketed hosts. A remote attacker could
    possibly use this issue to perform a Server-Side Request Forgery (SSRF) attack. This issue only affected
    python 2.7 and python3.4 on Ubuntu 14.04 LTS; python2.7 on Ubuntu 16.04 LTS; python2.7, python3.6,
    python3.7, and python3.8 on Ubuntu 18.04 LTS; python2.7 and python3.9 on Ubuntu 20.04 LTS; and python2.7
    and python3.11 on Ubuntu 22.04 LTS. (CVE-2024-11168)

    It was discovered that Python allowed excessive backtracking while parsing certain tarfile headers. A
    remote attacker could possibly use this issue to cause Python to consume excessive resources, leading to a
    denial of service. This issue only affected python3.4 on Ubuntu 14.04 LTS; python3.6, python3.7, and
    python3.8 on Ubuntu 18.04 LTS; python3.9 on Ubuntu 20.04 LTS; and python3.11 on Ubuntu 22.04 LTS.
    (CVE-2024-6232)

    It was discovered that Python incorrectly handled quoted path names when using the venv module. A local
    attacker able to control virtual environments could possibly use this issue to execute arbitrary code when
    the virtual environment is activated. This issue only affected python3.4 on Ubuntu 14.04 LTS; python3.6,
    python3.7, and python3.8 on Ubuntu 18.04 LTS; python3.9 on Ubuntu 20.04 LTS; python3.11 on Ubuntu 22.04
    LTS; and python3.13 on Ubuntu 24.10. (CVE-2024-9287)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7488-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/AU:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9287");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-11168");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.11-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.13-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.13-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.13-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.9-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.11-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.13-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.9-venv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04 / 20.04 / 22.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '14.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'idle-python3.4', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.4', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.4-dev', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.4-minimal', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.4-stdlib', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'libpython3.4-testsuite', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python2.7', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.6-8ubuntu0.6+esm24', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.4', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.4-dev', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.4-examples', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.4-minimal', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '14.04', 'pkgname': 'python3.4-venv', 'pkgver': '3.4.3-1ubuntu1~14.04.7+esm14', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm15', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'idle-python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'idle-python3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'idle-python3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-stdlib', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-testsuite', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7-dev', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7-minimal', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7-stdlib', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.7-testsuite', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8-dev', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8-minimal', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8-stdlib', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libpython3.8-testsuite', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.17-1~18.04ubuntu1.13+esm10', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6-examples', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.6-venv', 'pkgver': '3.6.9-1~18.04ubuntu1.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7-dev', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7-examples', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7-minimal', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.7-venv', 'pkgver': '3.7.5-2ubuntu1~18.04.2+esm4', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8-dev', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8-examples', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8-minimal', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3.8-venv', 'pkgver': '3.8.0-3ubuntu1~18.04.2+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'idle-python3.9', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython3.9', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython3.9-dev', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython3.9-minimal', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython3.9-stdlib', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpython3.9-testsuite', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python2.7', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.18-1~20.04.7+esm6', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python3.9', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python3.9-dev', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python3.9-examples', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python3.9-full', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python3.9-minimal', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'python3.9-venv', 'pkgver': '3.9.5-3ubuntu0~20.04.1+esm3', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'idle-python3.11', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython3.11', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython3.11-dev', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython3.11-minimal', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython3.11-stdlib', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpython3.11-testsuite', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python2.7', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.18-13ubuntu1.5+esm5', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python3.11', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python3.11-dev', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python3.11-examples', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python3.11-full', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python3.11-minimal', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python3.11-nopie', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'python3.11-venv', 'pkgver': '3.11.0~rc1-1~22.04.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '24.10', 'pkgname': 'idle-python3.13', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpython3.13', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpython3.13-dev', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpython3.13-minimal', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpython3.13-stdlib', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'libpython3.13-testsuite', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13-dev', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13-examples', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13-full', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13-gdbm', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13-minimal', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13-nopie', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13-tk', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '24.10', 'pkgname': 'python3.13-venv', 'pkgver': '3.13.0-1ubuntu0.1', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (deb_check(release:osver, prefix:pkgname, reference:pkgver, cves:cves)) {
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python2.7 / idle-python3.11 / idle-python3.13 / idle-python3.4 / etc');
}
