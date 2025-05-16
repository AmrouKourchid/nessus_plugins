#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4979-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150155);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2021-3428",
    "CVE-2021-3483",
    "CVE-2021-28660",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-28972",
    "CVE-2021-29647",
    "CVE-2021-31916",
    "CVE-2021-33033"
  );
  script_xref(name:"USN", value:"4979-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS : Linux kernel vulnerabilities (USN-4979-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-4979-1 advisory.

    Kiyin () discovered that the NFC LLCP protocol implementation in the Linux kernel contained a
    reference counting error. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2020-25670)

    Kiyin () discovered that the NFC LLCP protocol implementation in the Linux kernel did not properly
    deallocate memory in certain error situations. A local attacker could use this to cause a denial of
    service (memory exhaustion). (CVE-2020-25671, CVE-2020-25672)

    Kiyin () discovered that the NFC LLCP protocol implementation in the Linux kernel did not properly
    handle error conditions in some situations, leading to an infinite loop. A local attacker could use this
    to cause a denial of service. (CVE-2020-25673)

    It was discovered that the Realtek RTL8188EU Wireless device driver in the Linux kernel did not properly
    validate ssid lengths in some situations. An attacker could use this to cause a denial of service (system
    crash). (CVE-2021-28660)

    Zygo Blaxell discovered that the btrfs file system implementation in the Linux kernel contained a race
    condition during certain cloning operations. A local attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2021-28964)

    Vince Weaver discovered that the perf subsystem in the Linux kernel did not properly handle certain PEBS
    records properly for some Intel Haswell processors. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2021-28971)

    It was discovered that the RPA PCI Hotplug driver implementation in the Linux kernel did not properly
    handle device name writes via sysfs, leading to a buffer overflow. A privileged attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2021-28972)

    It was discovered that the Qualcomm IPC router implementation in the Linux kernel did not properly
    initialize memory passed to user space. A local attacker could use this to expose sensitive information
    (kernel memory). (CVE-2021-29647)

    Dan Carpenter discovered that the block device manager (dm) implementation in the Linux kernel contained a
    buffer overflow in the ioctl for listing devices. A privileged local attacker could use this to cause a
    denial of service (system crash). (CVE-2021-31916)

    It was discovered that the CIPSO implementation in the Linux kernel did not properly perform reference
    counting in some situations, leading to use- after-free vulnerabilities. An attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2021-33033)

    Wolfgang Frisch discovered that the ext4 file system implementation in the Linux kernel contained an
    integer overflow when handling metadata inode extents. An attacker could use this to construct a malicious
    ext4 file system image that, when mounted, could cause a denial of service (system crash). (CVE-2021-3428)

     discovered that the IEEE 1394 (Firewire) nosy packet sniffer driver in the Linux kernel did not
    properly perform reference counting in some situations, leading to a use-after-free vulnerability. A local
    attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2021-3483)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4979-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1072-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1086-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1092-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1100-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1103-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1103-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1115-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-144-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-144-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-144-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '4.15.0-144',
      'lowlatency': '4.15.0-144',
      'oracle': '4.15.0-1072',
      'gcp': '4.15.0-1100',
      'aws': '4.15.0-1103',
      'azure': '4.15.0-1115'
    }
  },
  '18.04': {
    '4.15.0': {
      'generic': '4.15.0-144',
      'generic-lpae': '4.15.0-144',
      'lowlatency': '4.15.0-144',
      'oracle': '4.15.0-1072',
      'raspi2': '4.15.0-1086',
      'kvm': '4.15.0-1092',
      'gcp': '4.15.0-1100',
      'snapdragon': '4.15.0-1103',
      'azure': '4.15.0-1115'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4979-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-25670', 'CVE-2020-25671', 'CVE-2020-25672', 'CVE-2020-25673', 'CVE-2021-3428', 'CVE-2021-3483', 'CVE-2021-28660', 'CVE-2021-28964', 'CVE-2021-28971', 'CVE-2021-28972', 'CVE-2021-29647', 'CVE-2021-31916', 'CVE-2021-33033');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4979-1');
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
