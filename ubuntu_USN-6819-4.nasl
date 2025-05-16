#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6819-4. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201042);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/08");

  script_cve_id(
    "CVE-2023-6356",
    "CVE-2023-6535",
    "CVE-2023-6536",
    "CVE-2023-52443",
    "CVE-2023-52444",
    "CVE-2023-52445",
    "CVE-2023-52446",
    "CVE-2023-52447",
    "CVE-2023-52448",
    "CVE-2023-52449",
    "CVE-2023-52450",
    "CVE-2023-52451",
    "CVE-2023-52452",
    "CVE-2023-52453",
    "CVE-2023-52454",
    "CVE-2023-52455",
    "CVE-2023-52456",
    "CVE-2023-52457",
    "CVE-2023-52458",
    "CVE-2023-52462",
    "CVE-2023-52463",
    "CVE-2023-52464",
    "CVE-2023-52465",
    "CVE-2023-52467",
    "CVE-2023-52468",
    "CVE-2023-52469",
    "CVE-2023-52470",
    "CVE-2023-52472",
    "CVE-2023-52473",
    "CVE-2023-52486",
    "CVE-2023-52487",
    "CVE-2023-52488",
    "CVE-2023-52489",
    "CVE-2023-52490",
    "CVE-2023-52491",
    "CVE-2023-52492",
    "CVE-2023-52493",
    "CVE-2023-52494",
    "CVE-2023-52495",
    "CVE-2023-52497",
    "CVE-2023-52498",
    "CVE-2023-52583",
    "CVE-2023-52584",
    "CVE-2023-52587",
    "CVE-2023-52588",
    "CVE-2023-52589",
    "CVE-2023-52591",
    "CVE-2023-52593",
    "CVE-2023-52594",
    "CVE-2023-52595",
    "CVE-2023-52597",
    "CVE-2023-52598",
    "CVE-2023-52599",
    "CVE-2023-52606",
    "CVE-2023-52607",
    "CVE-2023-52608",
    "CVE-2023-52609",
    "CVE-2023-52610",
    "CVE-2023-52611",
    "CVE-2023-52612",
    "CVE-2023-52614",
    "CVE-2023-52616",
    "CVE-2023-52617",
    "CVE-2023-52618",
    "CVE-2023-52619",
    "CVE-2023-52621",
    "CVE-2023-52622",
    "CVE-2023-52623",
    "CVE-2023-52626",
    "CVE-2023-52627",
    "CVE-2023-52632",
    "CVE-2023-52633",
    "CVE-2023-52635",
    "CVE-2023-52664",
    "CVE-2023-52666",
    "CVE-2023-52667",
    "CVE-2023-52669",
    "CVE-2023-52670",
    "CVE-2023-52672",
    "CVE-2023-52674",
    "CVE-2023-52675",
    "CVE-2023-52676",
    "CVE-2023-52677",
    "CVE-2023-52678",
    "CVE-2023-52679",
    "CVE-2023-52680",
    "CVE-2023-52681",
    "CVE-2023-52682",
    "CVE-2023-52683",
    "CVE-2023-52685",
    "CVE-2023-52686",
    "CVE-2023-52687",
    "CVE-2023-52690",
    "CVE-2023-52691",
    "CVE-2023-52692",
    "CVE-2023-52693",
    "CVE-2023-52694",
    "CVE-2023-52696",
    "CVE-2023-52697",
    "CVE-2023-52698",
    "CVE-2024-23849",
    "CVE-2024-24860",
    "CVE-2024-26582",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26586",
    "CVE-2024-26592",
    "CVE-2024-26594",
    "CVE-2024-26595",
    "CVE-2024-26598",
    "CVE-2024-26607",
    "CVE-2024-26608",
    "CVE-2024-26610",
    "CVE-2024-26612",
    "CVE-2024-26615",
    "CVE-2024-26616",
    "CVE-2024-26618",
    "CVE-2024-26620",
    "CVE-2024-26623",
    "CVE-2024-26625",
    "CVE-2024-26627",
    "CVE-2024-26629",
    "CVE-2024-26631",
    "CVE-2024-26632",
    "CVE-2024-26633",
    "CVE-2024-26634",
    "CVE-2024-26636",
    "CVE-2024-26638",
    "CVE-2024-26640",
    "CVE-2024-26641",
    "CVE-2024-26644",
    "CVE-2024-26645",
    "CVE-2024-26646",
    "CVE-2024-26647",
    "CVE-2024-26649",
    "CVE-2024-26668",
    "CVE-2024-26669",
    "CVE-2024-26670",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26808",
    "CVE-2024-35835",
    "CVE-2024-35837",
    "CVE-2024-35838",
    "CVE-2024-35839",
    "CVE-2024-35840",
    "CVE-2024-35841",
    "CVE-2024-35842"
  );
  script_xref(name:"USN", value:"6819-4");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel (Oracle) vulnerabilities (USN-6819-4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6819-4 advisory.

    Alon Zahavi discovered that the NVMe-oF/TCP subsystem in the Linux kernel did not properly validate H2C
    PDU data, leading to a null pointer dereference vulnerability. A remote attacker could use this to cause a
    denial of service (system crash). (CVE-2023-6356, CVE-2023-6535, CVE-2023-6536)

    Chenyuan Yang discovered that the RDS Protocol implementation in the Linux kernel contained an out-of-
    bounds read vulnerability. An attacker could use this to possibly cause a denial of service (system
    crash). (CVE-2024-23849)

    It was discovered that a race condition existed in the Bluetooth subsystem in the Linux kernel, leading to
    a null pointer dereference vulnerability. A privileged local attacker could use this to possibly cause a
    denial of service (system crash). (CVE-2024-24860)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - PowerPC architecture;

    - RISC-V architecture;

    - S390 architecture;

    - Core kernel;

    - x86 architecture;

    - Block layer subsystem;

    - Cryptographic API;

    - ACPI drivers;

    - Android drivers;

    - Drivers core;

    - Power management core;

    - Bus devices;

    - Device frequency scaling framework;

    - DMA engine subsystem;

    - EDAC drivers;

    - ARM SCMI message protocol;

    - GPU drivers;

    - IIO ADC drivers;

    - InfiniBand drivers;

    - IOMMU subsystem;

    - Media drivers;

    - Multifunction device drivers;

    - MTD block device drivers;

    - Network drivers;

    - NVME drivers;

    - Device tree and open firmware driver;

    - PCI driver for MicroSemi Switchtec;

    - Power supply drivers;

    - RPMSG subsystem;

    - SCSI drivers;

    - QCOM SoC drivers;

    - SPMI drivers;

    - Thermal drivers;

    - TTY drivers;

    - VFIO drivers;

    - BTRFS file system;

    - Ceph distributed file system;

    - EFI Variable file system;

    - EROFS file system;

    - Ext4 file system;

    - F2FS file system;

    - GFS2 file system;

    - JFS file system;

    - Network file systems library;

    - Network file system server daemon;

    - File systems infrastructure;

    - Pstore file system;

    - ReiserFS file system;

    - SMB network file system;

    - BPF subsystem;

    - Memory management;

    - TLS protocol;

    - Ethernet bridge;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - Logical Link layer;

    - MAC80211 subsystem;

    - Multipath TCP;

    - Netfilter;

    - NetLabel subsystem;

    - Network traffic control;

    - SMC sockets;

    - Sun RPC protocol;

    - AppArmor security module;

    - Intel ASoC drivers;

    - MediaTek ASoC drivers;

    - USB sound devices; (CVE-2023-52612, CVE-2024-26808, CVE-2023-52691, CVE-2023-52618, CVE-2023-52463,
    CVE-2023-52447, CVE-2024-26668, CVE-2023-52454, CVE-2024-26670, CVE-2024-26646, CVE-2023-52472,
    CVE-2024-26586, CVE-2023-52681, CVE-2023-52453, CVE-2023-52611, CVE-2023-52622, CVE-2024-26641,
    CVE-2023-52616, CVE-2024-26592, CVE-2023-52606, CVE-2024-26620, CVE-2023-52692, CVE-2024-26669,
    CVE-2023-52623, CVE-2023-52588, CVE-2024-26616, CVE-2024-26610, CVE-2024-35839, CVE-2023-52490,
    CVE-2023-52672, CVE-2024-26612, CVE-2023-52617, CVE-2023-52697, CVE-2024-26644, CVE-2023-52458,
    CVE-2023-52598, CVE-2024-35841, CVE-2023-52664, CVE-2023-52635, CVE-2023-52676, CVE-2023-52669,
    CVE-2024-26632, CVE-2023-52486, CVE-2024-26625, CVE-2023-52608, CVE-2024-26634, CVE-2023-52599,
    CVE-2024-26618, CVE-2024-26640, CVE-2023-52489, CVE-2023-52675, CVE-2023-52678, CVE-2024-26583,
    CVE-2023-52693, CVE-2023-52498, CVE-2024-26649, CVE-2023-52670, CVE-2023-52473, CVE-2023-52449,
    CVE-2023-52667, CVE-2023-52467, CVE-2023-52686, CVE-2024-26633, CVE-2023-52666, CVE-2024-35840,
    CVE-2024-26629, CVE-2024-26595, CVE-2023-52593, CVE-2023-52687, CVE-2023-52465, CVE-2024-26627,
    CVE-2023-52493, CVE-2023-52491, CVE-2024-26636, CVE-2024-26584, CVE-2023-52587, CVE-2023-52597,
    CVE-2023-52462, CVE-2023-52633, CVE-2023-52696, CVE-2024-26585, CVE-2023-52589, CVE-2023-52456,
    CVE-2023-52470, CVE-2024-35838, CVE-2024-26645, CVE-2023-52591, CVE-2023-52464, CVE-2023-52609,
    CVE-2024-26608, CVE-2023-52450, CVE-2023-52584, CVE-2023-52469, CVE-2023-52583, CVE-2023-52451,
    CVE-2023-52495, CVE-2023-52626, CVE-2023-52595, CVE-2023-52680, CVE-2023-52632, CVE-2024-26582,
    CVE-2024-35837, CVE-2023-52494, CVE-2023-52614, CVE-2023-52443, CVE-2023-52698, CVE-2023-52448,
    CVE-2024-26615, CVE-2023-52452, CVE-2023-52492, CVE-2024-26647, CVE-2023-52468, CVE-2023-52594,
    CVE-2023-52621, CVE-2024-26638, CVE-2024-26594, CVE-2024-26673, CVE-2023-52457, CVE-2023-52677,
    CVE-2023-52607, CVE-2024-26623, CVE-2023-52488, CVE-2023-52497, CVE-2023-52445, CVE-2024-26607,
    CVE-2023-52610, CVE-2024-35842, CVE-2023-52690, CVE-2023-52683, CVE-2023-52444, CVE-2024-26671,
    CVE-2023-52455, CVE-2023-52679, CVE-2024-26598, CVE-2023-52674, CVE-2023-52627, CVE-2023-52619,
    CVE-2023-52487, CVE-2023-52446, CVE-2024-35835, CVE-2023-52682, CVE-2023-52685, CVE-2023-52694,
    CVE-2024-26631)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6819-4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26625");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.5.0-1024-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.5.0-1024-oracle-64k");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'oracle': '6.5.0-1024',
      'oracle-64k': '6.5.0-1024'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6819-4');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-6356', 'CVE-2023-6535', 'CVE-2023-6536', 'CVE-2023-52443', 'CVE-2023-52444', 'CVE-2023-52445', 'CVE-2023-52446', 'CVE-2023-52447', 'CVE-2023-52448', 'CVE-2023-52449', 'CVE-2023-52450', 'CVE-2023-52451', 'CVE-2023-52452', 'CVE-2023-52453', 'CVE-2023-52454', 'CVE-2023-52455', 'CVE-2023-52456', 'CVE-2023-52457', 'CVE-2023-52458', 'CVE-2023-52462', 'CVE-2023-52463', 'CVE-2023-52464', 'CVE-2023-52465', 'CVE-2023-52467', 'CVE-2023-52468', 'CVE-2023-52469', 'CVE-2023-52470', 'CVE-2023-52472', 'CVE-2023-52473', 'CVE-2023-52486', 'CVE-2023-52487', 'CVE-2023-52488', 'CVE-2023-52489', 'CVE-2023-52490', 'CVE-2023-52491', 'CVE-2023-52492', 'CVE-2023-52493', 'CVE-2023-52494', 'CVE-2023-52495', 'CVE-2023-52497', 'CVE-2023-52498', 'CVE-2023-52583', 'CVE-2023-52584', 'CVE-2023-52587', 'CVE-2023-52588', 'CVE-2023-52589', 'CVE-2023-52591', 'CVE-2023-52593', 'CVE-2023-52594', 'CVE-2023-52595', 'CVE-2023-52597', 'CVE-2023-52598', 'CVE-2023-52599', 'CVE-2023-52606', 'CVE-2023-52607', 'CVE-2023-52608', 'CVE-2023-52609', 'CVE-2023-52610', 'CVE-2023-52611', 'CVE-2023-52612', 'CVE-2023-52614', 'CVE-2023-52616', 'CVE-2023-52617', 'CVE-2023-52618', 'CVE-2023-52619', 'CVE-2023-52621', 'CVE-2023-52622', 'CVE-2023-52623', 'CVE-2023-52626', 'CVE-2023-52627', 'CVE-2023-52632', 'CVE-2023-52633', 'CVE-2023-52635', 'CVE-2023-52664', 'CVE-2023-52666', 'CVE-2023-52667', 'CVE-2023-52669', 'CVE-2023-52670', 'CVE-2023-52672', 'CVE-2023-52674', 'CVE-2023-52675', 'CVE-2023-52676', 'CVE-2023-52677', 'CVE-2023-52678', 'CVE-2023-52679', 'CVE-2023-52680', 'CVE-2023-52681', 'CVE-2023-52682', 'CVE-2023-52683', 'CVE-2023-52685', 'CVE-2023-52686', 'CVE-2023-52687', 'CVE-2023-52690', 'CVE-2023-52691', 'CVE-2023-52692', 'CVE-2023-52693', 'CVE-2023-52694', 'CVE-2023-52696', 'CVE-2023-52697', 'CVE-2023-52698', 'CVE-2024-23849', 'CVE-2024-24860', 'CVE-2024-26582', 'CVE-2024-26583', 'CVE-2024-26584', 'CVE-2024-26585', 'CVE-2024-26586', 'CVE-2024-26592', 'CVE-2024-26594', 'CVE-2024-26595', 'CVE-2024-26598', 'CVE-2024-26607', 'CVE-2024-26608', 'CVE-2024-26610', 'CVE-2024-26612', 'CVE-2024-26615', 'CVE-2024-26616', 'CVE-2024-26618', 'CVE-2024-26620', 'CVE-2024-26623', 'CVE-2024-26625', 'CVE-2024-26627', 'CVE-2024-26629', 'CVE-2024-26631', 'CVE-2024-26632', 'CVE-2024-26633', 'CVE-2024-26634', 'CVE-2024-26636', 'CVE-2024-26638', 'CVE-2024-26640', 'CVE-2024-26641', 'CVE-2024-26644', 'CVE-2024-26645', 'CVE-2024-26646', 'CVE-2024-26647', 'CVE-2024-26649', 'CVE-2024-26668', 'CVE-2024-26669', 'CVE-2024-26670', 'CVE-2024-26671', 'CVE-2024-26673', 'CVE-2024-26808', 'CVE-2024-35835', 'CVE-2024-35837', 'CVE-2024-35838', 'CVE-2024-35839', 'CVE-2024-35840', 'CVE-2024-35841', 'CVE-2024-35842');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6819-4');
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
