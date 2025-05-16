#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6701-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192318);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2023-2002",
    "CVE-2023-3006",
    "CVE-2023-4132",
    "CVE-2023-6121",
    "CVE-2023-23000",
    "CVE-2023-34256",
    "CVE-2023-39197",
    "CVE-2023-46838",
    "CVE-2023-51781",
    "CVE-2024-0775",
    "CVE-2024-1086",
    "CVE-2024-24855"
  );
  script_xref(name:"USN", value:"6701-2");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/20");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel (GCP) vulnerabilities (USN-6701-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6701-2 advisory.

    Ruihan Li discovered that the bluetooth subsystem in the Linux kernel did not properly perform permissions
    checks when handling HCI sockets. A physically proximate attacker could use this to cause a denial of
    service (bluetooth communication). (CVE-2023-2002)

    It was discovered that the NVIDIA Tegra XUSB pad controller driver in the Linux kernel did not properly
    handle return values in certain error conditions. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2023-23000)

    It was discovered that Spectre-BHB mitigations were missing for Ampere processors. A local attacker could
    potentially use this to expose sensitive information. (CVE-2023-3006)

    It was discovered that the ext4 file system implementation in the Linux kernel did not properly handle
    block device modification while it is mounted. A privileged attacker could use this to cause a denial of
    service (system crash) or possibly expose sensitive information. (CVE-2023-34256)

    Eric Dumazet discovered that the netfilter subsystem in the Linux kernel did not properly handle DCCP
    conntrack buffers in certain situations, leading to an out-of-bounds read vulnerability. An attacker could
    possibly use this to expose sensitive information (kernel memory). (CVE-2023-39197)

    It was discovered that the Siano USB MDTV receiver device driver in the Linux kernel did not properly
    handle device initialization failures in certain situations, leading to a use-after-free vulnerability. A
    physically proximate attacker could use this cause a denial of service (system crash). (CVE-2023-4132)

    Pratyush Yadav discovered that the Xen network backend implementation in the Linux kernel did not properly
    handle zero length data request, leading to a null pointer dereference vulnerability. An attacker in a
    guest VM could possibly use this to cause a denial of service (host domain crash). (CVE-2023-46838)

    It was discovered that a race condition existed in the AppleTalk networking subsystem of the Linux kernel,
    leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2023-51781)

    Alon Zahavi discovered that the NVMe-oF/TCP subsystem of the Linux kernel did not properly handle connect
    command payloads in certain situations, leading to an out-of-bounds read vulnerability. A remote attacker
    could use this to expose sensitive information (kernel memory). (CVE-2023-6121)

    It was discovered that the ext4 file system implementation in the Linux kernel did not properly handle the
    remount operation in certain cases, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service (system crash) or possibly expose sensitive information. (CVE-2024-0775)

    Notselwyn discovered that the netfilter subsystem in the Linux kernel did not properly handle verdict
    parameters in certain cases, leading to a use- after-free vulnerability. A local attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2024-1086)

    It was discovered that a race condition existed in the SCSI Emulex LightPulse Fibre Channel driver in the
    Linux kernel when unregistering FCF and re-scanning an HBA FCF table, leading to a null pointer
    dereference vulnerability. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2024-24855)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6701-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39197");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-1086");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-2002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1160-gcp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '16.04': {
    '4.15.0': {
      'gcp': '4.15.0-1160'
    }
  },
  '18.04': {
    '4.15.0': {
      'gcp': '4.15.0-1160'
    }
  }
};

var host_kernel_release = get_kb_item('Host/uptrack-uname-r');
if (empty_or_null(host_kernel_release)) host_kernel_release = get_kb_item_or_exit('Host/uname-r');
var host_kernel_base_version = get_kb_item_or_exit('Host/Debian/kernel-base-version');
var host_kernel_type = get_kb_item_or_exit('Host/Debian/kernel-type');
if(empty_or_null(kernel_mappings[os_release][host_kernel_base_version][host_kernel_type])) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + host_kernel_release);

var extra = '';
var kernel_fixed_version = kernel_mappings[os_release][host_kernel_base_version][host_kernel_type] + "-" + host_kernel_type;
if (!ubuntu_pro_detected) {
  extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
  extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
  extra += 'require an Ubuntu Pro subscription.\n\n';
}
if (deb_ver_cmp(ver1:host_kernel_release, ver2:kernel_fixed_version) < 0)
{
  extra += 'Running Kernel level of ' + host_kernel_release + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6701-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-2002', 'CVE-2023-3006', 'CVE-2023-4132', 'CVE-2023-6121', 'CVE-2023-23000', 'CVE-2023-34256', 'CVE-2023-39197', 'CVE-2023-46838', 'CVE-2023-51781', 'CVE-2024-0775', 'CVE-2024-1086', 'CVE-2024-24855');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6701-2');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
