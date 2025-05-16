#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6458-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184019);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2022-29500", "CVE-2022-29501", "CVE-2022-29502");
  script_xref(name:"USN", value:"6458-1");

  script_name(english:"Ubuntu 20.04 ESM / 22.04 ESM : Slurm vulnerabilities (USN-6458-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 ESM / 22.04 ESM host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6458-1 advisory.

    It was discovered that Slurm did not properly handle credential management, which could allow an
    unprivileged user to impersonate the SlurmUser account. An attacker could possibly use this issue to
    execute arbitrary code as the root user. (CVE-2022-29500)

    It was discovered that Slurm did not properly handle access control when dealing with RPC traffic through
    PMI2 and PMIx, which could allow an unprivileged user to send data to an arbitrary unix socket in the
    host. An attacker could possibly use this issue to execute arbitrary code as the root user.
    (CVE-2022-29501)

    It was discovered that Slurm did not properly handle validation logic when processing input and output
    data with the srun client, which could lead to the interception of process I/O. An attacker could possibly
    use this issue to expose sensitive information or execute arbitrary code. This issue only affected Ubuntu
    22.04 LTS. (CVE-2022-29502)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6458-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29501");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-29502");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-slurm-adopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpmi0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpmi2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpmi2-0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurm-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurm34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurm37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslurmdb-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-client-emulator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm-basic-plugins-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm-emulator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurm-wlm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurmctld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slurmrestd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sview");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libpam-slurm', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpam-slurm-adopt', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpmi0', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpmi0-dev', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpmi2-0', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libpmi2-0-dev', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libslurm-dev', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libslurm-perl', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libslurm34', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'libslurmdb-perl', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurm-client', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurm-client-emulator', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurm-wlm', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurm-wlm-basic-plugins', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurm-wlm-basic-plugins-dev', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurm-wlm-emulator', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurm-wlm-torque', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurmctld', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurmd', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'slurmdbd', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'sview', 'pkgver': '19.05.5-1ubuntu0.1~esm2', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpam-slurm', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpam-slurm-adopt', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpmi0', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpmi0-dev', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpmi2-0', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libpmi2-0-dev', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libslurm-dev', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libslurm-perl', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libslurm37', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'libslurmdb-perl', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurm-client', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurm-client-emulator', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurm-wlm', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurm-wlm-basic-plugins', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurm-wlm-basic-plugins-dev', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurm-wlm-emulator', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurm-wlm-torque', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurmctld', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurmd', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurmdbd', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'slurmrestd', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE},
    {'osver': '22.04', 'pkgname': 'sview', 'pkgver': '21.08.5-2ubuntu1+esm1', 'ubuntu_pro': TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpam-slurm / libpam-slurm-adopt / libpmi0 / libpmi0-dev / etc');
}
