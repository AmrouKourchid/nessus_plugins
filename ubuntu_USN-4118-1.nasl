#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4118-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128478);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-13053",
    "CVE-2018-13093",
    "CVE-2018-13096",
    "CVE-2018-13097",
    "CVE-2018-13098",
    "CVE-2018-13099",
    "CVE-2018-13100",
    "CVE-2018-14609",
    "CVE-2018-14610",
    "CVE-2018-14611",
    "CVE-2018-14612",
    "CVE-2018-14613",
    "CVE-2018-14614",
    "CVE-2018-14615",
    "CVE-2018-14616",
    "CVE-2018-14617",
    "CVE-2018-16862",
    "CVE-2018-19985",
    "CVE-2018-20169",
    "CVE-2018-20511",
    "CVE-2018-20784",
    "CVE-2018-20856",
    "CVE-2018-5383",
    "CVE-2019-0136",
    "CVE-2019-10126",
    "CVE-2019-10207",
    "CVE-2019-10638",
    "CVE-2019-10639",
    "CVE-2019-11085",
    "CVE-2019-11487",
    "CVE-2019-11599",
    "CVE-2019-11810",
    "CVE-2019-11815",
    "CVE-2019-11833",
    "CVE-2019-11884",
    "CVE-2019-12818",
    "CVE-2019-12819",
    "CVE-2019-12984",
    "CVE-2019-13233",
    "CVE-2019-13272",
    "CVE-2019-13631",
    "CVE-2019-14283",
    "CVE-2019-14284",
    "CVE-2019-14763",
    "CVE-2019-15090",
    "CVE-2019-15211",
    "CVE-2019-15212",
    "CVE-2019-15214",
    "CVE-2019-15215",
    "CVE-2019-15216",
    "CVE-2019-15218",
    "CVE-2019-15220",
    "CVE-2019-15221",
    "CVE-2019-15292",
    "CVE-2019-2024",
    "CVE-2019-2101",
    "CVE-2019-3701",
    "CVE-2019-3819",
    "CVE-2019-3846",
    "CVE-2019-3900",
    "CVE-2019-9506"
  );
  script_xref(name:"USN", value:"4118-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/10");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel (AWS) vulnerabilities (USN-4118-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-4118-1 advisory.

    It was discovered that the alarmtimer implementation in the Linux kernel contained an integer overflow
    vulnerability. A local attacker could use this to cause a denial of service. (CVE-2018-13053)

    Wen Xu discovered that the XFS filesystem implementation in the Linux kernel did not properly track inode
    validations. An attacker could use this to construct a malicious XFS image that, when mounted, could cause
    a denial of service (system crash). (CVE-2018-13093)

    Wen Xu discovered that the f2fs file system implementation in the Linux kernel did not properly validate
    metadata. An attacker could use this to construct a malicious f2fs image that, when mounted, could cause a
    denial of service (system crash). (CVE-2018-13096, CVE-2018-13097, CVE-2018-13098, CVE-2018-13099,
    CVE-2018-13100, CVE-2018-14614, CVE-2018-14615, CVE-2018-14616)

    Wen Xu and Po-Ning Tseng discovered that btrfs file system implementation in the Linux kernel did not
    properly validate metadata. An attacker could use this to construct a malicious btrfs image that, when
    mounted, could cause a denial of service (system crash). (CVE-2018-14609, CVE-2018-14610, CVE-2018-14611,
    CVE-2018-14612, CVE-2018-14613)

    Wen Xu discovered that the HFS+ filesystem implementation in the Linux kernel did not properly handle
    malformed catalog data in some situations. An attacker could use this to construct a malicious HFS+ image
    that, when mounted, could cause a denial of service (system crash). (CVE-2018-14617)

    Vasily Averin and Pavel Tikhomirov discovered that the cleancache subsystem of the Linux kernel did not
    properly initialize new files in some situations. A local attacker could use this to expose sensitive
    information. (CVE-2018-16862)

    Hui Peng and Mathias Payer discovered that the Option USB High Speed driver in the Linux kernel did not
    properly validate metadata received from the device. A physically proximate attacker could use this to
    cause a denial of service (system crash). (CVE-2018-19985)

    Hui Peng and Mathias Payer discovered that the USB subsystem in the Linux kernel did not properly handle
    size checks when handling an extra USB descriptor. A physically proximate attacker could use this to cause
    a denial of service (system crash). (CVE-2018-20169)

    Zhipeng Xie discovered that an infinite loop could be triggered in the CFS Linux kernel process scheduler.
    A local attacker could possibly use this to cause a denial of service. (CVE-2018-20784)

    It was discovered that a use-after-free error existed in the block layer subsystem of the Linux kernel
    when certain failure conditions occurred. A local attacker could possibly use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2018-20856)

    Eli Biham and Lior Neumann discovered that the Bluetooth implementation in the Linux kernel did not
    properly validate elliptic curve parameters during Diffie-Hellman key exchange in some situations. An
    attacker could use this to expose sensitive information. (CVE-2018-5383)

    It was discovered that the Intel Wi-Fi device driver in the Linux kernel did not properly validate certain
    Tunneled Direct Link Setup (TDLS). A physically proximate attacker could use this to cause a denial of
    service (Wi-Fi disconnect). (CVE-2019-0136)

    It was discovered that a heap buffer overflow existed in the Marvell Wireless LAN device driver for the
    Linux kernel. An attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2019-10126)

    It was discovered that the Bluetooth UART implementation in the Linux kernel did not properly check for
    missing tty operations. A local attacker could use this to cause a denial of service. (CVE-2019-10207)

    Amit Klein and Benny Pinkas discovered that the Linux kernel did not sufficiently randomize IP ID values
    generated for connectionless networking protocols. A remote attacker could use this to track particular
    Linux devices. (CVE-2019-10638)

    Amit Klein and Benny Pinkas discovered that the location of kernel addresses could be exposed by the
    implementation of connection-less network protocols in the Linux kernel. A remote attacker could possibly
    use this to assist in the exploitation of another vulnerability in the Linux kernel. (CVE-2019-10639)

    Adam Zabrocki discovered that the Intel i915 kernel mode graphics driver in the Linux kernel did not
    properly restrict mmap() ranges in some situations. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2019-11085)

    It was discovered that an integer overflow existed in the Linux kernel when reference counting pages,
    leading to potential use-after-free issues. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2019-11487)

    Jann Horn discovered that a race condition existed in the Linux kernel when performing core dumps. A local
    attacker could use this to cause a denial of service (system crash) or expose sensitive information.
    (CVE-2019-11599)

    It was discovered that a null pointer dereference vulnerability existed in the LSI Logic MegaRAID driver
    in the Linux kernel. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2019-11810)

    It was discovered that a race condition leading to a use-after-free existed in the Reliable Datagram
    Sockets (RDS) protocol implementation in the Linux kernel. The RDS protocol is disabled via blocklist by
    default in Ubuntu.

    If enabled, a local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2019-11815)

    It was discovered that the ext4 file system implementation in the Linux kernel did not properly zero out
    memory in some situations. A local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2019-11833)

    It was discovered that the Bluetooth Human Interface Device Protocol (HIDP) implementation in the Linux
    kernel did not properly verify strings were NULL terminated in certain situations. A local attacker could
    use this to expose sensitive information (kernel memory). (CVE-2019-11884)

    It was discovered that a NULL pointer dereference vulnerabilty existed in the Near-field communication
    (NFC) implementation in the Linux kernel. An attacker could use this to cause a denial of service (system
    crash). (CVE-2019-12818)

    It was discovered that the MDIO bus devices subsystem in the Linux kernel improperly dropped a device
    reference in an error condition, leading to a use-after-free. An attacker could use this to cause a denial
    of service (system crash). (CVE-2019-12819)

    It was discovered that a NULL pointer dereference vulnerability existed in the Near-field communication
    (NFC) implementation in the Linux kernel. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2019-12984)

    Jann Horn discovered a use-after-free vulnerability in the Linux kernel when accessing LDT entries in some
    situations. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2019-13233)

    Jann Horn discovered that the ptrace implementation in the Linux kernel did not properly record
    credentials in some situations. A local attacker could use this to cause a denial of service (system
    crash) or possibly gain administrative privileges. (CVE-2019-13272)

    It was discovered that the GTCO tablet input driver in the Linux kernel did not properly bounds check the
    initial HID report sent by the device. A physically proximate attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2019-13631)

    It was discovered that the floppy driver in the Linux kernel did not properly validate meta data, leading
    to a buffer overread. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2019-14283)

    It was discovered that the floppy driver in the Linux kernel did not properly validate ioctl() calls,
    leading to a division-by-zero. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2019-14284)

    Tuba Yavuz discovered that a race condition existed in the DesignWare USB3 DRD Controller device driver in
    the Linux kernel. A physically proximate attacker could use this to cause a denial of service.
    (CVE-2019-14763)

    It was discovered that an out-of-bounds read existed in the QLogic QEDI iSCSI Initiator Driver in the
    Linux kernel. A local attacker could possibly use this to expose sensitive information (kernel memory).
    (CVE-2019-15090)

    It was discovered that the Raremono AM/FM/SW radio device driver in the Linux kernel did not properly
    allocate memory, leading to a use-after-free. A physically proximate attacker could use this to cause a
    denial of service or possibly execute arbitrary code. (CVE-2019-15211)

    It was discovered at a double-free error existed in the USB Rio 500 device driver for the Linux kernel. A
    physically proximate attacker could use this to cause a denial of service. (CVE-2019-15212)

    It was discovered that a race condition existed in the Advanced Linux Sound Architecture (ALSA) subsystem
    of the Linux kernel, leading to a potential use-after-free. A physically proximate attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-15214)

    It was discovered that a race condition existed in the CPiA2 video4linux device driver for the Linux
    kernel, leading to a use-after-free. A physically proximate attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2019-15215)

    It was discovered that a race condition existed in the Softmac USB Prism54 device driver in the Linux
    kernel. A physically proximate attacker could use this to cause a denial of service (system crash).
    (CVE-2019-15220)

    It was discovered that a use-after-free vulnerability existed in the AppleTalk implementation in the Linux
    kernel if an error occurs during initialization. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2019-15292)

    It was discovered that the Empia EM28xx DVB USB device driver implementation in the Linux kernel contained
    a use-after-free vulnerability when disconnecting the device. An attacker could use this to cause a denial
    of service (system crash). (CVE-2019-2024)

    It was discovered that the USB video device class implementation in the Linux kernel did not properly
    validate control bits, resulting in an out of bounds buffer read. A local attacker could use this to
    possibly expose sensitive information (kernel memory). (CVE-2019-2101)

    It was discovered that the Marvell Wireless LAN device driver in the Linux kernel did not properly
    validate the BSS descriptor. A local attacker could possibly use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2019-3846)

    Jason Wang discovered that an infinite loop vulnerability existed in the virtio net driver in the Linux
    kernel. A local attacker in a guest VM could possibly use this to cause a denial of service in the host
    system. (CVE-2019-3900)

    Daniele Antonioli, Nils Ole Tippenhauer, and Kasper B. Rasmussen discovered that the Bluetooth protocol
    BR/EDR specification did not properly require sufficiently strong encryption key lengths. A physically
    proximate attacker could use this to expose sensitive information. (CVE-2019-9506)

    It was discovered that the Appletalk IP encapsulation driver in the Linux kernel did not properly prevent
    kernel addresses from being copied to user space. A local attacker with the CAP_NET_ADMIN capability could
    use this to expose sensitive information. (CVE-2018-20511)

    It was discovered that a race condition existed in the USB YUREX device driver in the Linux kernel. A
    physically proximate attacker could use this to cause a denial of service (system crash). (CVE-2019-15216)

    It was discovered that the Siano USB MDTV receiver device driver in the Linux kernel made improper
    assumptions about the device characteristics. A physically proximate attacker could use this cause a
    denial of service (system crash). (CVE-2019-15218)

    It was discovered that the Line 6 POD USB device driver in the Linux kernel did not properly validate data
    size information from the device. A physically proximate attacker could use this to cause a denial of
    service (system crash). (CVE-2019-15221)

    Muyu Yu discovered that the CAN implementation in the Linux kernel in some situations did not properly
    restrict the field size when processing outgoing frames. A local attacker with CAP_NET_ADMIN privileges
    could use this to execute arbitrary code. (CVE-2019-3701)

    Vladis Dronov discovered that the debug interface for the Linux kernel's HID subsystem did not properly
    validate passed parameters in some situations. A local privileged attacker could use this to cause a
    denial of service (infinite loop). (CVE-2019-3819)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4118-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15292");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10126");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Polkit pkexec helper PTRACE_TRACEME local root exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1047-aws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '16.04': {
    '4.15.0': {
      'aws': '4.15.0-1047'
    }
  },
  '18.04': {
    '4.15.0': {
      'aws': '4.15.0-1047'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4118-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2018-5383', 'CVE-2018-13053', 'CVE-2018-13093', 'CVE-2018-13096', 'CVE-2018-13097', 'CVE-2018-13098', 'CVE-2018-13099', 'CVE-2018-13100', 'CVE-2018-14609', 'CVE-2018-14610', 'CVE-2018-14611', 'CVE-2018-14612', 'CVE-2018-14613', 'CVE-2018-14614', 'CVE-2018-14615', 'CVE-2018-14616', 'CVE-2018-14617', 'CVE-2018-16862', 'CVE-2018-19985', 'CVE-2018-20169', 'CVE-2018-20511', 'CVE-2018-20784', 'CVE-2018-20856', 'CVE-2019-0136', 'CVE-2019-2024', 'CVE-2019-2101', 'CVE-2019-3701', 'CVE-2019-3819', 'CVE-2019-3846', 'CVE-2019-3900', 'CVE-2019-9506', 'CVE-2019-10126', 'CVE-2019-10207', 'CVE-2019-10638', 'CVE-2019-10639', 'CVE-2019-11085', 'CVE-2019-11487', 'CVE-2019-11599', 'CVE-2019-11810', 'CVE-2019-11815', 'CVE-2019-11833', 'CVE-2019-11884', 'CVE-2019-12818', 'CVE-2019-12819', 'CVE-2019-12984', 'CVE-2019-13233', 'CVE-2019-13272', 'CVE-2019-13631', 'CVE-2019-14283', 'CVE-2019-14284', 'CVE-2019-14763', 'CVE-2019-15090', 'CVE-2019-15211', 'CVE-2019-15212', 'CVE-2019-15214', 'CVE-2019-15215', 'CVE-2019-15216', 'CVE-2019-15218', 'CVE-2019-15220', 'CVE-2019-15221', 'CVE-2019-15292');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4118-1');
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
