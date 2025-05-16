#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6256-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178920);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/19");

  script_cve_id(
    "CVE-2022-3108",
    "CVE-2022-3707",
    "CVE-2022-3903",
    "CVE-2022-4129",
    "CVE-2023-0458",
    "CVE-2023-0459",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1077",
    "CVE-2023-1078",
    "CVE-2023-1079",
    "CVE-2023-1118",
    "CVE-2023-1281",
    "CVE-2023-1380",
    "CVE-2023-1513",
    "CVE-2023-1670",
    "CVE-2023-1829",
    "CVE-2023-1859",
    "CVE-2023-1998",
    "CVE-2023-2162",
    "CVE-2023-2612",
    "CVE-2023-2985",
    "CVE-2023-3161",
    "CVE-2023-25012",
    "CVE-2023-26545",
    "CVE-2023-30456",
    "CVE-2023-31436",
    "CVE-2023-32233",
    "CVE-2023-32269",
    "CVE-2023-35788"
  );
  script_xref(name:"USN", value:"6256-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (IoT) vulnerabilities (USN-6256-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6256-1 advisory.

    Jiasheng Jiang discovered that the HSA Linux kernel driver for AMD Radeon GPU devices did not properly
    validate memory allocation in certain situations, leading to a null pointer dereference vulnerability. A
    local attacker could use this to cause a denial of service (system crash). (CVE-2022-3108)

    Zheng Wang discovered that the Intel i915 graphics driver in the Linux kernel did not properly handle
    certain error conditions, leading to a double-free. A local attacker could possibly use this to cause a
    denial of service (system crash). (CVE-2022-3707)

    It was discovered that the infrared transceiver USB driver did not properly handle USB control messages. A
    local attacker with physical access could plug in a specially crafted USB device to cause a denial of
    service (memory exhaustion). (CVE-2022-3903)

    Haowei Yan discovered that a race condition existed in the Layer 2 Tunneling Protocol (L2TP)
    implementation in the Linux kernel. A local attacker could possibly use this to cause a denial of service
    (system crash). (CVE-2022-4129)

    Jordy Zomer and Alexandra Sandulescu discovered that syscalls invoking the do_prlimit() function in the
    Linux kernel did not properly handle speculative execution barriers. A local attacker could use this to
    expose sensitive information (kernel memory). (CVE-2023-0458)

    Jordy Zomer and Alexandra Sandulescu discovered that the Linux kernel did not properly implement
    speculative execution barriers in usercopy functions in certain situations. A local attacker could use
    this to expose sensitive information (kernel memory). (CVE-2023-0459)

    It was discovered that the Human Interface Device (HID) support driver in the Linux kernel contained a
    type confusion vulnerability in some situations. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2023-1073)

    It was discovered that a memory leak existed in the SCTP protocol implementation in the Linux kernel. A
    local attacker could use this to cause a denial of service (memory exhaustion). (CVE-2023-1074)

    It was discovered that the TLS subsystem in the Linux kernel contained a type confusion vulnerability in
    some situations. A local attacker could use this to cause a denial of service (system crash) or possibly
    expose sensitive information. (CVE-2023-1075)

    It was discovered that the TUN/TAP driver in the Linux kernel did not properly initialize socket data. A
    local attacker could use this to cause a denial of service (system crash). (CVE-2023-1076)

    It was discovered that the Real-Time Scheduling Class implementation in the Linux kernel contained a type
    confusion vulnerability in some situations. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2023-1077)

    It was discovered that the Reliable Datagram Sockets (RDS) protocol implementation in the Linux kernel
    contained a type confusion vulnerability in some situations. An attacker could use this to cause a denial
    of service (system crash). (CVE-2023-1078)

    It was discovered that the ASUS HID driver in the Linux kernel did not properly handle device removal,
    leading to a use-after-free vulnerability. A local attacker with physical access could plug in a specially
    crafted USB device to cause a denial of service (system crash). (CVE-2023-1079)

    Duoming Zhou discovered that a race condition existed in the infrared receiver/transceiver driver in the
    Linux kernel, leading to a use-after- free vulnerability. A privileged attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-1118)

    It was discovered that the Traffic-Control Index (TCINDEX) implementation in the Linux kernel contained a
    use-after-free vulnerability. A local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2023-1281)

    It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux kernel did not properly perform
    data buffer size validation in some situations. A physically proximate attacker could use this to craft a
    malicious USB device that when inserted, could cause a denial of service (system crash) or possibly expose
    sensitive information. (CVE-2023-1380)

    Xingyuan Mo discovered that the x86 KVM implementation in the Linux kernel did not properly initialize
    some data structures. A local attacker could use this to expose sensitive information (kernel memory).
    (CVE-2023-1513)

    It was discovered that the Xircom PCMCIA network device driver in the Linux kernel did not properly handle
    device removal events. A physically proximate attacker could use this to cause a denial of service (system
    crash). (CVE-2023-1670)

    It was discovered that the Traffic-Control Index (TCINDEX) implementation in the Linux kernel did not
    properly perform filter deactivation in some situations. A local attacker could possibly use this to gain
    elevated privileges. Please note that with the fix for this CVE, kernel support for the TCINDEX classifier
    has been removed. (CVE-2023-1829)

    It was discovered that a race condition existed in the Xen transport layer implementation for the 9P file
    system protocol in the Linux kernel, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service (guest crash) or expose sensitive information (guest kernel memory).
    (CVE-2023-1859)

    Jose Oliveira and Rodrigo Branco discovered that the Spectre Variant 2 mitigations with prctl syscall were
    insufficient in some situations. A local attacker could possibly use this to expose sensitive information.
    (CVE-2023-1998)

    It was discovered that a use-after-free vulnerability existed in the iSCSI TCP implementation in the Linux
    kernel. A local attacker could possibly use this to cause a denial of service (system crash).
    (CVE-2023-2162)

    It was discovered that the BigBen Interactive Kids' gamepad driver in the Linux kernel did not properly
    handle device removal, leading to a use- after-free vulnerability. A local attacker with physical access
    could plug in a specially crafted USB device to cause a denial of service (system crash). (CVE-2023-25012)

    Jean-Baptiste Cayrou discovered that the shiftfs file system in the Ubuntu Linux kernel contained a race
    condition when handling inode locking in some situations. A local attacker could use this to cause a
    denial of service (kernel deadlock). (CVE-2023-2612)

    Lianhui Tang discovered that the MPLS implementation in the Linux kernel did not properly handle certain
    sysctl allocation failure conditions, leading to a double-free vulnerability. An attacker could use this
    to cause a denial of service or possibly execute arbitrary code. (CVE-2023-26545)

    It was discovered that a use-after-free vulnerability existed in the HFS+ file system implementation in
    the Linux kernel. A local attacker could possibly use this to cause a denial of service (system crash).
    (CVE-2023-2985)

    Reima Ishii discovered that the nested KVM implementation for Intel x86 processors in the Linux kernel did
    not properly validate control registers in certain situations. An attacker in a guest VM could use this to
    cause a denial of service (guest crash). (CVE-2023-30456)

    Gwangun Jung discovered that the Quick Fair Queueing scheduler implementation in the Linux kernel
    contained an out-of-bounds write vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2023-31436)

    Sanan Hasanov discovered that the framebuffer console driver in the Linux kernel did not properly perform
    checks for font dimension limits. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2023-3161)

    Patryk Sondej and Piotr Krysiuk discovered that a race condition existed in the netfilter subsystem of the
    Linux kernel when processing batch requests, leading to a use-after-free vulnerability. A local attacker
    could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2023-32233)

    It was discovered that the NET/ROM protocol implementation in the Linux kernel contained a race condition
    in some situations, leading to a use- after-free vulnerability. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-32269)

    Hangyu Hua discovered that the Flower classifier implementation in the Linux kernel contained an out-of-
    bounds write vulnerability. An attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2023-35788, LP: #2023577)

    It was discovered that for some Intel processors the INVLPG instruction implementation did not properly
    flush global TLB entries when PCIDs are enabled. An attacker could use this to expose sensitive
    information (kernel memory) or possibly cause undesired behaviors. (LP: #2023220)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6256-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1079");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-35788");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-35788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1017-iot");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.4.0': {
      'iot': '5.4.0-1017'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6256-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3108', 'CVE-2022-3707', 'CVE-2022-3903', 'CVE-2022-4129', 'CVE-2023-0458', 'CVE-2023-0459', 'CVE-2023-1073', 'CVE-2023-1074', 'CVE-2023-1075', 'CVE-2023-1076', 'CVE-2023-1077', 'CVE-2023-1078', 'CVE-2023-1079', 'CVE-2023-1118', 'CVE-2023-1281', 'CVE-2023-1380', 'CVE-2023-1513', 'CVE-2023-1670', 'CVE-2023-1829', 'CVE-2023-1859', 'CVE-2023-1998', 'CVE-2023-2162', 'CVE-2023-2612', 'CVE-2023-2985', 'CVE-2023-3161', 'CVE-2023-25012', 'CVE-2023-26545', 'CVE-2023-30456', 'CVE-2023-31436', 'CVE-2023-32233', 'CVE-2023-32269', 'CVE-2023-35788');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6256-1');
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
