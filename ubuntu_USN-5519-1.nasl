##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5519-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163104);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2015-20107");
  script_xref(name:"USN", value:"5519-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS : Python vulnerability (USN-5519-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by a
vulnerability as referenced in the USN-5519-1 advisory.

    It was discovered that Python incorrectly handled certain inputs. An attacker could possibly use this
    issue to execute arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5519-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.10-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-nopie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.10-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-venv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'idle-python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5-stdlib', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libpython3.5-testsuite', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.18+esm2', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5-examples', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python3.5-venv', 'pkgver': '3.5.2-2ubuntu0~16.04.13+esm3', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'idle-python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-stdlib', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'libpython3.6-testsuite', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.17-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python3.6-examples', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python3.6-venv', 'pkgver': '3.6.9-1~18.04ubuntu1.8', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'idle-python3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8-dev', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8-minimal', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8-stdlib', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libpython3.8-testsuite', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python2.7', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.18-1~20.04.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-dev', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-examples', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-full', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-minimal', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3.8-venv', 'pkgver': '3.8.10-0ubuntu1~20.04.5', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'idle-python3.10', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10-dev', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10-minimal', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10-stdlib', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libpython3.10-testsuite', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python2.7', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.18-13ubuntu1.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-dev', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-examples', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-full', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-minimal', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-nopie', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3.10-venv', 'pkgver': '3.10.4-3ubuntu0.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python2.7 / idle-python3.10 / idle-python3.5 / idle-python3.6 / etc');
}
