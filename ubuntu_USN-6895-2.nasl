#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6895-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202477);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2023-6270",
    "CVE-2023-52631",
    "CVE-2023-52637",
    "CVE-2023-52638",
    "CVE-2023-52642",
    "CVE-2023-52643",
    "CVE-2023-52645",
    "CVE-2023-52880",
    "CVE-2024-0841",
    "CVE-2024-1151",
    "CVE-2024-23307",
    "CVE-2024-24861",
    "CVE-2024-26593",
    "CVE-2024-26600",
    "CVE-2024-26601",
    "CVE-2024-26602",
    "CVE-2024-26603",
    "CVE-2024-26606",
    "CVE-2024-26642",
    "CVE-2024-26659",
    "CVE-2024-26660",
    "CVE-2024-26661",
    "CVE-2024-26662",
    "CVE-2024-26663",
    "CVE-2024-26664",
    "CVE-2024-26665",
    "CVE-2024-26666",
    "CVE-2024-26667",
    "CVE-2024-26674",
    "CVE-2024-26675",
    "CVE-2024-26676",
    "CVE-2024-26677",
    "CVE-2024-26679",
    "CVE-2024-26680",
    "CVE-2024-26681",
    "CVE-2024-26684",
    "CVE-2024-26685",
    "CVE-2024-26688",
    "CVE-2024-26689",
    "CVE-2024-26691",
    "CVE-2024-26693",
    "CVE-2024-26694",
    "CVE-2024-26695",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26698",
    "CVE-2024-26700",
    "CVE-2024-26702",
    "CVE-2024-26703",
    "CVE-2024-26707",
    "CVE-2024-26708",
    "CVE-2024-26710",
    "CVE-2024-26711",
    "CVE-2024-26712",
    "CVE-2024-26714",
    "CVE-2024-26715",
    "CVE-2024-26716",
    "CVE-2024-26717",
    "CVE-2024-26718",
    "CVE-2024-26719",
    "CVE-2024-26720",
    "CVE-2024-26722",
    "CVE-2024-26723",
    "CVE-2024-26726",
    "CVE-2024-26733",
    "CVE-2024-26734",
    "CVE-2024-26735",
    "CVE-2024-26736",
    "CVE-2024-26748",
    "CVE-2024-26782",
    "CVE-2024-26789",
    "CVE-2024-26790",
    "CVE-2024-26792",
    "CVE-2024-26798",
    "CVE-2024-26802",
    "CVE-2024-26803",
    "CVE-2024-26818",
    "CVE-2024-26820",
    "CVE-2024-26822",
    "CVE-2024-26824",
    "CVE-2024-26825",
    "CVE-2024-26826",
    "CVE-2024-26828",
    "CVE-2024-26829",
    "CVE-2024-26830",
    "CVE-2024-26831",
    "CVE-2024-26838",
    "CVE-2024-26889",
    "CVE-2024-26890",
    "CVE-2024-26898",
    "CVE-2024-26910",
    "CVE-2024-26916",
    "CVE-2024-26917",
    "CVE-2024-26919",
    "CVE-2024-26920",
    "CVE-2024-26922",
    "CVE-2024-26923",
    "CVE-2024-26926",
    "CVE-2024-27416",
    "CVE-2024-35833"
  );
  script_xref(name:"USN", value:"6895-2");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-6895-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6895-2 advisory.

    It was discovered that the ATA over Ethernet (AoE) driver in the Linux kernel contained a race condition,
    leading to a use-after-free vulnerability. An attacker could use this to cause a denial of service or
    possibly execute arbitrary code. (CVE-2023-6270)

    It was discovered that the HugeTLB file system component of the Linux Kernel contained a NULL pointer
    dereference vulnerability. A privileged attacker could possibly use this to to cause a denial of service.
    (CVE-2024-0841)

    It was discovered that the Open vSwitch implementation in the Linux kernel could overflow its stack during
    recursive action operations under certain conditions. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2024-1151)

    Gui-Dong Han discovered that the software RAID driver in the Linux kernel contained a race condition,
    leading to an integer overflow vulnerability. A privileged attacker could possibly use this to cause a
    denial of service (system crash). (CVE-2024-23307)

    Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in the Linux kernel contained a
    race condition, leading to an integer overflow vulnerability. An attacker could possibly use this to cause
    a denial of service (system crash). (CVE-2024-24861)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - PowerPC architecture;

    - x86 architecture;

    - Cryptographic API;

    - Android drivers;

    - Block layer subsystem;

    - Bluetooth drivers;

    - DMA engine subsystem;

    - GPU drivers;

    - HID subsystem;

    - Hardware monitoring drivers;

    - I2C subsystem;

    - IIO ADC drivers;

    - IIO subsystem;

    - IIO Magnetometer sensors drivers;

    - InfiniBand drivers;

    - On-Chip Interconnect management framework;

    - Multiple devices driver;

    - Media drivers;

    - Network drivers;

    - PHY drivers;

    - MediaTek PM domains;

    - SCSI drivers;

    - TTY drivers;

    - USB subsystem;

    - DesignWare USB3 driver;

    - Framebuffer layer;

    - AFS file system;

    - BTRFS file system;

    - Ceph distributed file system;

    - Ext4 file system;

    - File systems infrastructure;

    - NILFS2 file system;

    - NTFS3 file system;

    - SMB network file system;

    - Core kernel;

    - Memory management;

    - Bluetooth subsystem;

    - CAN network layer;

    - Devlink API;

    - Handshake API;

    - HSR network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - Multipath TCP;

    - Netfilter;

    - NFC subsystem;

    - RxRPC session sockets;

    - TIPC protocol;

    - Unix domain sockets;

    - Realtek audio codecs; (CVE-2024-26684, CVE-2024-26889, CVE-2024-26662, CVE-2024-26660, CVE-2024-26708,
    CVE-2024-26677, CVE-2024-26696, CVE-2024-26664, CVE-2024-26642, CVE-2023-52637, CVE-2024-26680,
    CVE-2024-26822, CVE-2023-52638, CVE-2024-26830, CVE-2024-26715, CVE-2024-26693, CVE-2024-26697,
    CVE-2024-26694, CVE-2024-26685, CVE-2023-52642, CVE-2024-26691, CVE-2024-26798, CVE-2024-26828,
    CVE-2024-26663, CVE-2024-26710, CVE-2024-26601, CVE-2024-26707, CVE-2024-26802, CVE-2024-26675,
    CVE-2024-26826, CVE-2024-26916, CVE-2024-26803, CVE-2024-26700, CVE-2024-26917, CVE-2024-26600,
    CVE-2024-26825, CVE-2024-26716, CVE-2024-26602, CVE-2024-26698, CVE-2024-26711, CVE-2024-26920,
    CVE-2024-26722, CVE-2024-26681, CVE-2024-26674, CVE-2024-26712, CVE-2024-26735, CVE-2024-26782,
    CVE-2024-26734, CVE-2024-26926, CVE-2024-26923, CVE-2023-52880, CVE-2024-26719, CVE-2024-26593,
    CVE-2024-26603, CVE-2024-26922, CVE-2024-26717, CVE-2024-26695, CVE-2023-52643, CVE-2024-35833,
    CVE-2024-26733, CVE-2024-26667, CVE-2024-26659, CVE-2024-26714, CVE-2024-26748, CVE-2024-26702,
    CVE-2024-26676, CVE-2024-26718, CVE-2024-27416, CVE-2024-26890, CVE-2024-26720, CVE-2024-26838,
    CVE-2024-26665, CVE-2024-26792, CVE-2024-26818, CVE-2024-26679, CVE-2024-26606, CVE-2024-26736,
    CVE-2024-26829, CVE-2023-52631, CVE-2024-26790, CVE-2024-26824, CVE-2024-26820, CVE-2024-26831,
    CVE-2024-26689, CVE-2024-26898, CVE-2024-26789, CVE-2024-26703, CVE-2023-52645, CVE-2024-26688,
    CVE-2024-26723, CVE-2024-26919, CVE-2024-26661, CVE-2024-26726, CVE-2024-26910, CVE-2024-26666)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6895-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.5.0-1024-gcp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '6.5.0': {
      'gcp': '6.5.0-1024'
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
if (deb_ver_cmp(ver1:host_kernel_release, ver2:kernel_fixed_version) < 0)
{
  extra += 'Running Kernel level of ' + host_kernel_release + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6895-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-6270', 'CVE-2023-52631', 'CVE-2023-52637', 'CVE-2023-52638', 'CVE-2023-52642', 'CVE-2023-52643', 'CVE-2023-52645', 'CVE-2023-52880', 'CVE-2024-0841', 'CVE-2024-1151', 'CVE-2024-23307', 'CVE-2024-24861', 'CVE-2024-26593', 'CVE-2024-26600', 'CVE-2024-26601', 'CVE-2024-26602', 'CVE-2024-26603', 'CVE-2024-26606', 'CVE-2024-26642', 'CVE-2024-26659', 'CVE-2024-26660', 'CVE-2024-26661', 'CVE-2024-26662', 'CVE-2024-26663', 'CVE-2024-26664', 'CVE-2024-26665', 'CVE-2024-26666', 'CVE-2024-26667', 'CVE-2024-26674', 'CVE-2024-26675', 'CVE-2024-26676', 'CVE-2024-26677', 'CVE-2024-26679', 'CVE-2024-26680', 'CVE-2024-26681', 'CVE-2024-26684', 'CVE-2024-26685', 'CVE-2024-26688', 'CVE-2024-26689', 'CVE-2024-26691', 'CVE-2024-26693', 'CVE-2024-26694', 'CVE-2024-26695', 'CVE-2024-26696', 'CVE-2024-26697', 'CVE-2024-26698', 'CVE-2024-26700', 'CVE-2024-26702', 'CVE-2024-26703', 'CVE-2024-26707', 'CVE-2024-26708', 'CVE-2024-26710', 'CVE-2024-26711', 'CVE-2024-26712', 'CVE-2024-26714', 'CVE-2024-26715', 'CVE-2024-26716', 'CVE-2024-26717', 'CVE-2024-26718', 'CVE-2024-26719', 'CVE-2024-26720', 'CVE-2024-26722', 'CVE-2024-26723', 'CVE-2024-26726', 'CVE-2024-26733', 'CVE-2024-26734', 'CVE-2024-26735', 'CVE-2024-26736', 'CVE-2024-26748', 'CVE-2024-26782', 'CVE-2024-26789', 'CVE-2024-26790', 'CVE-2024-26792', 'CVE-2024-26798', 'CVE-2024-26802', 'CVE-2024-26803', 'CVE-2024-26818', 'CVE-2024-26820', 'CVE-2024-26822', 'CVE-2024-26824', 'CVE-2024-26825', 'CVE-2024-26826', 'CVE-2024-26828', 'CVE-2024-26829', 'CVE-2024-26830', 'CVE-2024-26831', 'CVE-2024-26838', 'CVE-2024-26889', 'CVE-2024-26890', 'CVE-2024-26898', 'CVE-2024-26910', 'CVE-2024-26916', 'CVE-2024-26917', 'CVE-2024-26919', 'CVE-2024-26920', 'CVE-2024-26922', 'CVE-2024-26923', 'CVE-2024-26926', 'CVE-2024-27416', 'CVE-2024-35833');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6895-2');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
