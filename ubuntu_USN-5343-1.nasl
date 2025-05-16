#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5343-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159160);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-2853",
    "CVE-2016-2854",
    "CVE-2018-5995",
    "CVE-2019-19449",
    "CVE-2020-12655",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2020-26139",
    "CVE-2020-26147",
    "CVE-2020-26555",
    "CVE-2020-26558",
    "CVE-2020-36322",
    "CVE-2020-36385",
    "CVE-2021-0129",
    "CVE-2021-3483",
    "CVE-2021-3506",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3612",
    "CVE-2021-3679",
    "CVE-2021-20292",
    "CVE-2021-20317",
    "CVE-2021-23134",
    "CVE-2021-28688",
    "CVE-2021-28972",
    "CVE-2021-29650",
    "CVE-2021-32399",
    "CVE-2021-33033",
    "CVE-2021-33034",
    "CVE-2021-33098",
    "CVE-2021-34693",
    "CVE-2021-38160",
    "CVE-2021-38198",
    "CVE-2021-38204",
    "CVE-2021-38208",
    "CVE-2021-39648",
    "CVE-2021-40490",
    "CVE-2021-42008",
    "CVE-2021-43389",
    "CVE-2021-45095",
    "CVE-2021-45469",
    "CVE-2021-45485",
    "CVE-2022-0492"
  );
  script_xref(name:"USN", value:"5343-1");

  script_name(english:"Ubuntu 16.04 ESM : Linux kernel vulnerabilities (USN-5343-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5343-1 advisory.

    Yiqi Sun and Kevin Wang discovered that the cgroups implementation in the Linux kernel did not properly
    restrict access to the cgroups v1 release_agent feature. A local attacker could use this to gain
    administrative privileges. (CVE-2022-0492)

    It was discovered that the aufs file system in the Linux kernel did not properly restrict mount
    namespaces, when mounted with the non-default allow_userns option set. A local attacker could use this to
    gain administrative privileges. (CVE-2016-2853)

    It was discovered that the aufs file system in the Linux kernel did not properly maintain POSIX ACL xattr
    data, when mounted with the non-default allow_userns option. A local attacker could possibly use this to
    gain elevated privileges. (CVE-2016-2854)

    It was discovered that the f2fs file system in the Linux kernel did not properly validate metadata in some
    situations. An attacker could use this to construct a malicious f2fs image that, when mounted and operated
    on, could cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-19449)

    It was discovered that the XFS file system implementation in the Linux kernel did not properly validate
    meta data in some circumstances. An attacker could use this to construct a malicious XFS image that, when
    mounted, could cause a denial of service. (CVE-2020-12655)

    Kiyin () discovered that the NFC LLCP protocol implementation in the Linux kernel contained a
    reference counting error. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2020-25670)

    Kiyin () discovered that the NFC LLCP protocol implementation in the Linux kernel did not properly
    deallocate memory in certain error situations. A local attacker could use this to cause a denial of
    service (memory exhaustion). (CVE-2020-25671, CVE-2020-25672)

    Kiyin () discovered that the NFC LLCP protocol implementation in the Linux kernel did not properly
    handle error conditions in some situations, leading to an infinite loop. A local attacker could use this
    to cause a denial of service. (CVE-2020-25673)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation incorrectly handled EAPOL frames
    from unauthenticated senders. A physically proximate attacker could inject malicious packets to cause a
    denial of service (system crash). (CVE-2020-26139)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation could reassemble mixed encrypted
    and plaintext fragments. A physically proximate attacker could possibly use this issue to inject packets
    or exfiltrate selected fragments. (CVE-2020-26147)

    It was discovered that the BR/EDR pin-code pairing procedure in the Linux kernel was vulnerable to an
    impersonation attack. A physically proximate attacker could possibly use this to pair to a device without
    knowledge of the pin-code. (CVE-2020-26555)

    It was discovered that the bluetooth subsystem in the Linux kernel did not properly perform access
    control. An authenticated attacker could possibly use this to expose sensitive information.
    (CVE-2020-26558, CVE-2021-0129)

    It was discovered that the FUSE user space file system implementation in the Linux kernel did not properly
    handle bad inodes in some situations. A local attacker could possibly use this to cause a denial of
    service. (CVE-2020-36322)

    It was discovered that the Infiniband RDMA userspace connection manager implementation in the Linux kernel
    contained a race condition leading to a use-after-free vulnerability. A local attacker could use this to
    cause a denial of service (system crash) or possible execute arbitrary code. (CVE-2020-36385)

    It was discovered that the DRM subsystem in the Linux kernel contained double-free vulnerabilities. A
    privileged attacker could possibly use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2021-20292)

    It was discovered that a race condition existed in the timer implementation in the Linux kernel. A
    privileged attacker could use this to cause a denial of service. (CVE-2021-20317)

    Or Cohen and Nadav Markus discovered a use-after-free vulnerability in the nfc implementation in the Linux
    kernel. A privileged local attacker could use this issue to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2021-23134)

    It was discovered that the Xen paravirtualization backend in the Linux kernel did not properly deallocate
    memory in some situations. A local attacker could use this to cause a denial of service (memory
    exhaustion). (CVE-2021-28688)

    It was discovered that the RPA PCI Hotplug driver implementation in the Linux kernel did not properly
    handle device name writes via sysfs, leading to a buffer overflow. A privileged attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2021-28972)

    It was discovered that a race condition existed in the netfilter subsystem of the Linux kernel when
    replacing tables. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2021-29650)

    It was discovered that a race condition in the kernel Bluetooth subsystem could lead to use-after-free of
    slab objects. An attacker could use this issue to possibly execute arbitrary code. (CVE-2021-32399)

    It was discovered that the CIPSO implementation in the Linux kernel did not properly perform reference
    counting in some situations, leading to use- after-free vulnerabilities. An attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2021-33033)

    It was discovered that a use-after-free existed in the Bluetooth HCI driver of the Linux kernel. A local
    attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2021-33034)

    Asaf Modelevsky discovered that the Intel(R) Ethernet ixgbe driver for the Linux kernel did not properly
    validate large MTU requests from Virtual Function (VF) devices. A local attacker could possibly use this
    to cause a denial of service. (CVE-2021-33098)

    Norbert Slusarek discovered that the CAN broadcast manger (bcm) protocol implementation in the Linux
    kernel did not properly initialize memory in some situations. A local attacker could use this to expose
    sensitive information (kernel memory). (CVE-2021-34693)

     discovered that the IEEE 1394 (Firewire) nosy packet sniffer driver in the Linux kernel did not
    properly perform reference counting in some situations, leading to a use-after-free vulnerability. A local
    attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2021-3483)

    It was discovered that an out-of-bounds (OOB) memory access flaw existed in the f2fs module of the Linux
    kernel. A local attacker could use this issue to cause a denial of service (system crash). (CVE-2021-3506)

    It was discovered that the bluetooth subsystem in the Linux kernel did not properly handle HCI device
    initialization failure, leading to a double-free vulnerability. An attacker could use this to cause a
    denial of service or possibly execute arbitrary code. (CVE-2021-3564)

    It was discovered that the bluetooth subsystem in the Linux kernel did not properly handle HCI device
    detach events, leading to a use-after-free vulnerability. An attacker could use this to cause a denial of
    service or possibly execute arbitrary code. (CVE-2021-3573)

    Murray McAllister discovered that the joystick device interface in the Linux kernel did not properly
    validate data passed via an ioctl(). A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code on systems with a joystick device registered. (CVE-2021-3612)

    It was discovered that the tracing subsystem in the Linux kernel did not properly keep track of per-cpu
    ring buffer state. A privileged attacker could use this to cause a denial of service. (CVE-2021-3679)

    It was discovered that the Virtio console implementation in the Linux kernel did not properly validate
    input lengths in some situations. A local attacker could possibly use this to cause a denial of service
    (system crash). (CVE-2021-38160)

    It was discovered that the KVM hypervisor implementation in the Linux kernel did not properly compute the
    access permissions for shadow pages in some situations. A local attacker could use this to cause a denial
    of service. (CVE-2021-38198)

    It was discovered that the MAX-3421 host USB device driver in the Linux kernel did not properly handle
    device removal events. A physically proximate attacker could use this to cause a denial of service (system
    crash). (CVE-2021-38204)

    It was discovered that the NFC implementation in the Linux kernel did not properly handle failed connect
    events leading to a NULL pointer dereference. A local attacker could use this to cause a denial of
    service. (CVE-2021-38208)

    It was discovered that the configfs interface for USB gadgets in the Linux kernel contained a race
    condition. A local attacker could possibly use this to expose sensitive information (kernel memory).
    (CVE-2021-39648)

    It was discovered that the ext4 file system in the Linux kernel contained a race condition when writing
    xattrs to an inode. A local attacker could use this to cause a denial of service or possibly gain
    administrative privileges. (CVE-2021-40490)

    It was discovered that the 6pack network protocol driver in the Linux kernel did not properly perform
    validation checks. A privileged attacker could use this to cause a denial of service (system crash) or
    execute arbitrary code. (CVE-2021-42008)

    It was discovered that the ISDN CAPI implementation in the Linux kernel contained a race condition in
    certain situations that could trigger an array out-of-bounds bug. A privileged local attacker could
    possibly use this to cause a denial of service or execute arbitrary code. (CVE-2021-43389)

    It was discovered that the Phone Network protocol (PhoNet) implementation in the Linux kernel did not
    properly perform reference counting in some error conditions. A local attacker could possibly use this to
    cause a denial of service (memory exhaustion). (CVE-2021-45095)

    Wenqing Liu discovered that the f2fs file system in the Linux kernel did not properly validate the last
    xattr entry in an inode. An attacker could use this to construct a malicious f2fs image that, when mounted
    and operated on, could cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2021-45469)

    Amit Klein discovered that the IPv6 implementation in the Linux kernel could disclose internal state in
    some situations. An attacker could possibly use this to expose sensitive information. (CVE-2021-45485)

    It was discovered that the per cpu memory allocator in the Linux kernel could report kernel pointers via
    dmesg. An attacker could use this to expose sensitive information or in conjunction with another kernel
    vulnerability. (CVE-2018-5995)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5343-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38160");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Docker cgroups Container Escape');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1103-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-222-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-222-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
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
      'generic': '4.4.0-222',
      'lowlatency': '4.4.0-222',
      'kvm': '4.4.0-1103',
      'aws': '4.4.0-1138'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5343-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2016-2853', 'CVE-2016-2854', 'CVE-2018-5995', 'CVE-2019-19449', 'CVE-2020-12655', 'CVE-2020-25670', 'CVE-2020-25671', 'CVE-2020-25672', 'CVE-2020-25673', 'CVE-2020-26139', 'CVE-2020-26147', 'CVE-2020-26555', 'CVE-2020-26558', 'CVE-2020-36322', 'CVE-2020-36385', 'CVE-2021-0129', 'CVE-2021-3483', 'CVE-2021-3506', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3612', 'CVE-2021-3679', 'CVE-2021-20292', 'CVE-2021-20317', 'CVE-2021-23134', 'CVE-2021-28688', 'CVE-2021-28972', 'CVE-2021-29650', 'CVE-2021-32399', 'CVE-2021-33033', 'CVE-2021-33034', 'CVE-2021-33098', 'CVE-2021-34693', 'CVE-2021-38160', 'CVE-2021-38198', 'CVE-2021-38204', 'CVE-2021-38208', 'CVE-2021-39648', 'CVE-2021-40490', 'CVE-2021-42008', 'CVE-2021-43389', 'CVE-2021-45095', 'CVE-2021-45469', 'CVE-2021-45485', 'CVE-2022-0492');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5343-1');
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
