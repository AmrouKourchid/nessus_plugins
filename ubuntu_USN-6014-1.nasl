#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6014-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174228);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-36516",
    "CVE-2021-3428",
    "CVE-2021-3659",
    "CVE-2021-3669",
    "CVE-2021-3732",
    "CVE-2021-3772",
    "CVE-2021-4149",
    "CVE-2021-4203",
    "CVE-2021-26401",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-45868",
    "CVE-2022-0487",
    "CVE-2022-0494",
    "CVE-2022-0617",
    "CVE-2022-1016",
    "CVE-2022-1195",
    "CVE-2022-1205",
    "CVE-2022-1462",
    "CVE-2022-1516",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-2318",
    "CVE-2022-2380",
    "CVE-2022-2503",
    "CVE-2022-2663",
    "CVE-2022-2991",
    "CVE-2022-3061",
    "CVE-2022-3111",
    "CVE-2022-3303",
    "CVE-2022-3628",
    "CVE-2022-3646",
    "CVE-2022-3903",
    "CVE-2022-4662",
    "CVE-2022-20132",
    "CVE-2022-20572",
    "CVE-2022-36280",
    "CVE-2022-36879",
    "CVE-2022-39188",
    "CVE-2022-41218",
    "CVE-2022-41849",
    "CVE-2022-41850",
    "CVE-2022-47929",
    "CVE-2023-0394",
    "CVE-2023-1074",
    "CVE-2023-1095",
    "CVE-2023-1118",
    "CVE-2023-23455",
    "CVE-2023-26545",
    "CVE-2023-26607"
  );
  script_xref(name:"USN", value:"6014-1");

  script_name(english:"Ubuntu 16.04 ESM : Linux kernel vulnerabilities (USN-6014-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6014-1 advisory.

    Xuewei Feng, Chuanpu Fu, Qi Li, Kun Sun, and Ke Xu discovered that the TCP implementation in the Linux
    kernel did not properly handle IPID assignment. A remote attacker could use this to cause a denial of
    service (connection termination) or inject forged data. (CVE-2020-36516)

    Ke Sun, Alyssa Milburn, Henrique Kawakami, Emma Benoit, Igor Chervatyuk, Lisa Aichele, and Thais Moreira
    Hamasaki discovered that the Spectre Variant 2 mitigations for AMD processors on Linux were insufficient
    in some situations. A local attacker could possibly use this to expose sensitive information.
    (CVE-2021-26401)

    Jrgen Gro discovered that the Xen subsystem within the Linux kernel did not adequately limit the
    number of events driver domains (unprivileged PV backends) could send to other guest VMs. An attacker in a
    driver domain could use this to cause a denial of service in other guest VMs. (CVE-2021-28711,
    CVE-2021-28712, CVE-2021-28713)

    Wolfgang Frisch discovered that the ext4 file system implementation in the Linux kernel contained an
    integer overflow when handling metadata inode extents. An attacker could use this to construct a malicious
    ext4 file system image that, when mounted, could cause a denial of service (system crash). (CVE-2021-3428)

    It was discovered that the IEEE 802.15.4 wireless network subsystem in the Linux kernel did not properly
    handle certain error conditions, leading to a null pointer dereference vulnerability. A local attacker
    could possibly use this to cause a denial of service (system crash). (CVE-2021-3659)

    It was discovered that the System V IPC implementation in the Linux kernel did not properly handle large
    shared memory counts. A local attacker could use this to cause a denial of service (memory exhaustion).
    (CVE-2021-3669)

    Alois Wohlschlager discovered that the overlay file system in the Linux kernel did not restrict private
    clones in some situations. An attacker could use this to expose sensitive information. (CVE-2021-3732)

    It was discovered that the SCTP protocol implementation in the Linux kernel did not properly verify VTAGs
    in some situations. A remote attacker could possibly use this to cause a denial of service (connection
    disassociation). (CVE-2021-3772)

    It was discovered that the btrfs file system implementation in the Linux kernel did not properly handle
    locking in certain error conditions. A local attacker could use this to cause a denial of service (kernel
    deadlock). (CVE-2021-4149)

    Jann Horn discovered that the socket subsystem in the Linux kernel contained a race condition when
    handling listen() and connect() operations, leading to a read-after-free vulnerability. A local attacker
    could use this to cause a denial of service (system crash) or possibly expose sensitive information.
    (CVE-2021-4203)

    It was discovered that the file system quotas implementation in the Linux kernel did not properly validate
    the quota block number. An attacker could use this to construct a malicious file system image that, when
    mounted and operated on, could cause a denial of service (system crash). (CVE-2021-45868)

    Zhihua Yao discovered that the MOXART SD/MMC driver in the Linux kernel did not properly handle device
    removal, leading to a use-after-free vulnerability. A physically proximate attacker could possibly use
    this to cause a denial of service (system crash). (CVE-2022-0487)

    It was discovered that the block layer subsystem in the Linux kernel did not properly initialize memory in
    some situations. A privileged local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2022-0494)

    It was discovered that the UDF file system implementation in the Linux kernel could attempt to dereference
    a null pointer in some situations. An attacker could use this to construct a malicious UDF image that,
    when mounted and operated on, could cause a denial of service (system crash). (CVE-2022-0617)

    David Bouman discovered that the netfilter subsystem in the Linux kernel did not initialize memory in some
    situations. A local attacker could use this to expose sensitive information (kernel memory).
    (CVE-2022-1016)

    It was discovered that the implementation of the 6pack and mkiss protocols in the Linux kernel did not
    handle detach events properly in some situations, leading to a use-after-free vulnerability. A local
    attacker could possibly use this to cause a denial of service (system crash). (CVE-2022-1195)

    Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol implementation in the Linux
    kernel, leading to use-after-free vulnerabilities. A local attacker could possibly use this to cause a
    denial of service (system crash). (CVE-2022-1205)

    It was discovered that the tty subsystem in the Linux kernel contained a race condition in certain
    situations, leading to an out-of-bounds read vulnerability. A local attacker could possibly use this to
    cause a denial of service (system crash) or expose sensitive information. (CVE-2022-1462)

    It was discovered that the implementation of X.25 network protocols in the Linux kernel did not terminate
    link layer sessions properly. A local attacker could possibly use this to cause a denial of service
    (system crash). (CVE-2022-1516)

    Duoming Zhou discovered a race condition in the NFC subsystem in the Linux kernel, leading to a use-after-
    free vulnerability. A privileged local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2022-1974)

    Duoming Zhou discovered that the NFC subsystem in the Linux kernel did not properly prevent context
    switches from occurring during certain atomic context operations. A privileged local attacker could use
    this to cause a denial of service (system crash). (CVE-2022-1975)

    It was discovered that the HID subsystem in the Linux kernel did not properly validate inputs in certain
    conditions. A local attacker with physical access could plug in a specially crafted USB device to expose
    sensitive information. (CVE-2022-20132)

    It was discovered that the device-mapper verity (dm-verity) driver in the Linux kernel did not properly
    verify targets being loaded into the device- mapper table. A privileged attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-20572, CVE-2022-2503)

    Duoming Zhou discovered that race conditions existed in the timer handling implementation of the Linux
    kernel's Rose X.25 protocol layer, resulting in use-after-free vulnerabilities. A local attacker could use
    this to cause a denial of service (system crash). (CVE-2022-2318)

    Zheyu Ma discovered that the Silicon Motion SM712 framebuffer driver in the Linux kernel did not properly
    handle very small reads. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-2380)

    David Leadbeater discovered that the netfilter IRC protocol tracking implementation in the Linux Kernel
    incorrectly handled certain message payloads in some situations. A remote attacker could possibly use this
    to cause a denial of service or bypass firewall filtering. (CVE-2022-2663)

    Lucas Leong discovered that the LightNVM subsystem in the Linux kernel did not properly handle data
    lengths in certain situations. A privileged attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2022-2991)

    It was discovered that the Intel 740 frame buffer driver in the Linux kernel contained a divide by zero
    vulnerability. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-3061)

    Jiasheng Jiang discovered that the wm8350 charger driver in the Linux kernel did not properly deallocate
    memory, leading to a null pointer dereference vulnerability. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2022-3111)

    It was discovered that the sound subsystem in the Linux kernel contained a race condition in some
    situations. A local attacker could use this to cause a denial of service (system crash). (CVE-2022-3303)

    It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux kernel did not properly perform
    bounds checking in some situations. A physically proximate attacker could use this to craft a malicious
    USB device that when inserted, could cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2022-3628)

    Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux kernel contained an out-of-
    bounds write vulnerability. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-36280)

    It was discovered that the NILFS2 file system implementation in the Linux kernel did not properly
    deallocate memory in certain error conditions. An attacker could use this to cause a denial of service
    (memory exhaustion). (CVE-2022-3646)

    It was discovered that the Netlink Transformation (XFRM) subsystem in the Linux kernel contained a
    reference counting error. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-36879)

    It was discovered that the infrared transceiver USB driver did not properly handle USB control messages. A
    local attacker with physical access could plug in a specially crafted USB device to cause a denial of
    service (memory exhaustion). (CVE-2022-3903)

    Jann Horn discovered a race condition existed in the Linux kernel when unmapping VMAs in certain
    situations, resulting in possible use-after-free vulnerabilities. A local attacker could possibly use this
    to cause a denial of service (system crash) or execute arbitrary code. (CVE-2022-39188)

    Hyunwoo Kim discovered that the DVB Core driver in the Linux kernel did not properly perform reference
    counting in some situations, leading to a use- after-free vulnerability. A local attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-41218)

    It was discovered that a race condition existed in the SMSC UFX USB driver implementation in the Linux
    kernel, leading to a use-after-free vulnerability. A physically proximate attacker could use this to cause
    a denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-41849)

    It was discovered that a race condition existed in the Roccat HID driver in the Linux kernel, leading to a
    use-after-free vulnerability. A local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2022-41850)

    It was discovered that the USB core subsystem in the Linux kernel did not properly handle nested reset
    events. A local attacker with physical access could plug in a specially crafted USB device to cause a
    denial of service (kernel deadlock). (CVE-2022-4662)

    It was discovered that the network queuing discipline implementation in the Linux kernel contained a null
    pointer dereference in some situations. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2022-47929)

    Kyle Zeng discovered that the IPv6 implementation in the Linux kernel contained a NULL pointer dereference
    vulnerability in certain situations. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2023-0394)

    It was discovered that a memory leak existed in the SCTP protocol implementation in the Linux kernel. A
    local attacker could use this to cause a denial of service (memory exhaustion). (CVE-2023-1074)

    Mingi Cho discovered that the netfilter subsystem in the Linux kernel did not properly initialize a data
    structure, leading to a null pointer dereference vulnerability. An attacker could use this to cause a
    denial of service (system crash). (CVE-2023-1095)

    Kyle Zeng discovered that the ATM VC queuing discipline implementation in the Linux kernel contained a
    type confusion vulnerability in some situations. An attacker could use this to cause a denial of service
    (system crash). (CVE-2023-23455)

    Lianhui Tang discovered that the MPLS implementation in the Linux kernel did not properly handle certain
    sysctl allocation failure conditions, leading to a double-free vulnerability. An attacker could use this
    to cause a denial of service or possibly execute arbitrary code. (CVE-2023-26545)

    It was discovered that the NTFS file system implementation in the Linux kernel did not properly validate
    attributes in certain situations, leading to an out-of-bounds read vulnerability. A local attacker could
    possibly use this to expose sensitive information (kernel memory). (CVE-2023-26607)

    Duoming Zhou discovered that a race condition existed in the infrared receiver/transceiver driver in the
    Linux kernel, leading to a use-after- free vulnerability. A privileged attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-1118)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6014-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3772");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1118");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1118-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-239-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-239-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '16.04': {
    '4.4.0': {
      'generic': '4.4.0-239',
      'lowlatency': '4.4.0-239',
      'kvm': '4.4.0-1118'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6014-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-36516', 'CVE-2021-3428', 'CVE-2021-3659', 'CVE-2021-3669', 'CVE-2021-3732', 'CVE-2021-3772', 'CVE-2021-4149', 'CVE-2021-4203', 'CVE-2021-26401', 'CVE-2021-28711', 'CVE-2021-28712', 'CVE-2021-28713', 'CVE-2021-45868', 'CVE-2022-0487', 'CVE-2022-0494', 'CVE-2022-0617', 'CVE-2022-1016', 'CVE-2022-1195', 'CVE-2022-1205', 'CVE-2022-1462', 'CVE-2022-1516', 'CVE-2022-1974', 'CVE-2022-1975', 'CVE-2022-2318', 'CVE-2022-2380', 'CVE-2022-2503', 'CVE-2022-2663', 'CVE-2022-2991', 'CVE-2022-3061', 'CVE-2022-3111', 'CVE-2022-3303', 'CVE-2022-3628', 'CVE-2022-3646', 'CVE-2022-3903', 'CVE-2022-4662', 'CVE-2022-20132', 'CVE-2022-20572', 'CVE-2022-36280', 'CVE-2022-36879', 'CVE-2022-39188', 'CVE-2022-41218', 'CVE-2022-41849', 'CVE-2022-41850', 'CVE-2022-47929', 'CVE-2023-0394', 'CVE-2023-1074', 'CVE-2023-1095', 'CVE-2023-1118', 'CVE-2023-23455', 'CVE-2023-26545', 'CVE-2023-26607');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6014-1');
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
