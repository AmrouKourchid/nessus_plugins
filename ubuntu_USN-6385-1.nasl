#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6385-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181636);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2022-4269",
    "CVE-2022-27672",
    "CVE-2023-0458",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1206",
    "CVE-2023-1380",
    "CVE-2023-1611",
    "CVE-2023-2002",
    "CVE-2023-2162",
    "CVE-2023-2163",
    "CVE-2023-2235",
    "CVE-2023-2269",
    "CVE-2023-2898",
    "CVE-2023-3090",
    "CVE-2023-3141",
    "CVE-2023-3220",
    "CVE-2023-3390",
    "CVE-2023-3609",
    "CVE-2023-3610",
    "CVE-2023-3611",
    "CVE-2023-3776",
    "CVE-2023-3777",
    "CVE-2023-3863",
    "CVE-2023-3995",
    "CVE-2023-4004",
    "CVE-2023-4015",
    "CVE-2023-4128",
    "CVE-2023-4194",
    "CVE-2023-4273",
    "CVE-2023-4569",
    "CVE-2023-20593",
    "CVE-2023-28328",
    "CVE-2023-28466",
    "CVE-2023-31436",
    "CVE-2023-32269",
    "CVE-2023-40283"
  );
  script_xref(name:"USN", value:"6385-1");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel (OEM) vulnerabilities (USN-6385-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6385-1 advisory.

    It was discovered that some AMD x86-64 processors with SMT enabled could speculatively execute
    instructions using a return address from a sibling thread. A local attacker could possibly use this to
    expose sensitive information. (CVE-2022-27672)

    William Zhao discovered that the Traffic Control (TC) subsystem in the Linux kernel did not properly
    handle network packet retransmission in certain situations. A local attacker could use this to cause a
    denial of service (kernel deadlock). (CVE-2022-4269)

    Jordy Zomer and Alexandra Sandulescu discovered that syscalls invoking the do_prlimit() function in the
    Linux kernel did not properly handle speculative execution barriers. A local attacker could use this to
    expose sensitive information (kernel memory). (CVE-2023-0458)

    It was discovered that the TLS subsystem in the Linux kernel contained a type confusion vulnerability in
    some situations. A local attacker could use this to cause a denial of service (system crash) or possibly
    expose sensitive information. (CVE-2023-1075)

    It was discovered that the TUN/TAP driver in the Linux kernel did not properly initialize socket data. A
    local attacker could use this to cause a denial of service (system crash). (CVE-2023-1076, CVE-2023-4194)

    It was discovered that the IPv6 implementation in the Linux kernel contained a high rate of hash
    collisions in connection lookup table. A remote attacker could use this to cause a denial of service
    (excessive CPU consumption). (CVE-2023-1206)

    It was discovered that the Broadcom FullMAC USB WiFi driver in the Linux kernel did not properly perform
    data buffer size validation in some situations. A physically proximate attacker could use this to craft a
    malicious USB device that when inserted, could cause a denial of service (system crash) or possibly expose
    sensitive information. (CVE-2023-1380)

    It was discovered that a race condition existed in the btrfs file system implementation in the Linux
    kernel, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly expose sensitive information. (CVE-2023-1611)

    Ruihan Li discovered that the bluetooth subsystem in the Linux kernel did not properly perform permissions
    checks when handling HCI sockets. A physically proximate attacker could use this to cause a denial of
    service (bluetooth communication). (CVE-2023-2002)

    Tavis Ormandy discovered that some AMD processors did not properly handle speculative execution of certain
    vector register instructions. A local attacker could use this to expose sensitive information.
    (CVE-2023-20593)

    It was discovered that a use-after-free vulnerability existed in the iSCSI TCP implementation in the Linux
    kernel. A local attacker could possibly use this to cause a denial of service (system crash).
    (CVE-2023-2162)

    Juan Jose Lopez Jaimez, Meador Inge, Simon Scannell, and Nenad Stojanovski discovered that the BPF
    verifier in the Linux kernel did not properly mark registers for precision tracking in certain situations,
    leading to an out- of-bounds access vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2023-2163)

    It was discovered that the perf subsystem in the Linux kernel contained a use-after-free vulnerability. A
    privileged local attacker could possibly use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2023-2235)

    Zheng Zhang discovered that the device-mapper implementation in the Linux kernel did not properly handle
    locking during table_clear() operations. A local attacker could use this to cause a denial of service
    (kernel deadlock). (CVE-2023-2269)

    Wei Chen discovered that the DVB USB AZ6027 driver in the Linux kernel contained a null pointer
    dereference when handling certain messages from user space. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2023-28328)

    It was discovered that a race condition existed in the TLS subsystem in the Linux kernel, leading to a
    use-after-free or a null pointer dereference vulnerability. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-28466)

    It was discovered that a race condition existed in the f2fs file system in the Linux kernel, leading to a
    null pointer dereference vulnerability. An attacker could use this to construct a malicious f2fs image
    that, when mounted and operated on, could cause a denial of service (system crash). (CVE-2023-2898)

    It was discovered that the IP-VLAN network driver for the Linux kernel did not properly initialize memory
    in some situations, leading to an out-of- bounds write vulnerability. An attacker could use this to cause
    a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-3090)

    It was discovered that the Ricoh R5C592 MemoryStick card reader driver in the Linux kernel contained a
    race condition during module unload, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-3141)

    Gwangun Jung discovered that the Quick Fair Queueing scheduler implementation in the Linux kernel
    contained an out-of-bounds write vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2023-31436)

    It was discovered that the Qualcomm MSM DPU driver in the Linux kernel did not properly validate memory
    allocations in certain situations, leading to a null pointer dereference vulnerability. A local attacker
    could use this to cause a denial of service (system crash). (CVE-2023-3220)

    It was discovered that the NET/ROM protocol implementation in the Linux kernel contained a race condition
    in some situations, leading to a use- after-free vulnerability. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-32269)

    It was discovered that the netfilter subsystem in the Linux kernel did not properly handle some error
    conditions, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2023-3390)

    It was discovered that the universal 32bit network packet classifier implementation in the Linux kernel
    did not properly perform reference counting in some situations, leading to a use-after-free vulnerability.
    A local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2023-3609)

    It was discovered that the netfilter subsystem in the Linux kernel did not properly handle certain error
    conditions, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2023-3610)

    It was discovered that the Quick Fair Queueing network scheduler implementation in the Linux kernel
    contained an out-of-bounds write vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2023-3611)

    It was discovered that the network packet classifier with netfilter/firewall marks implementation in the
    Linux kernel did not properly handle reference counting, leading to a use-after-free vulnerability. A
    local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2023-3776)

    Kevin Rich discovered that the netfilter subsystem in the Linux kernel did not properly handle table rules
    flush in certain circumstances. A local attacker could possibly use this to cause a denial of service
    (system crash) or execute arbitrary code. (CVE-2023-3777)

    It was discovered that the NFC implementation in the Linux kernel contained a use-after-free vulnerability
    when performing peer-to-peer communication in certain conditions. A privileged attacker could use this to
    cause a denial of service (system crash) or possibly expose sensitive information (kernel memory).
    (CVE-2023-3863)

    Kevin Rich discovered that the netfilter subsystem in the Linux kernel did not properly handle rule
    additions to bound chains in certain circumstances. A local attacker could possibly use this to cause a
    denial of service (system crash) or execute arbitrary code. (CVE-2023-3995)

    It was discovered that the netfilter subsystem in the Linux kernel did not properly handle PIPAPO element
    removal, leading to a use-after-free vulnerability. A local attacker could possibly use this to cause a
    denial of service (system crash) or execute arbitrary code. (CVE-2023-4004)

    Kevin Rich discovered that the netfilter subsystem in the Linux kernel did not properly handle bound chain
    deactivation in certain circumstances. A local attacker could possibly use this to cause a denial of
    service (system crash) or execute arbitrary code. (CVE-2023-4015)

    It was discovered that the bluetooth subsystem in the Linux kernel did not properly handle L2CAP socket
    release, leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2023-40283)

    It was discovered that some network classifier implementations in the Linux kernel contained use-after-
    free vulnerabilities. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2023-4128)

    Maxim Suhanov discovered that the exFAT file system implementation in the Linux kernel did not properly
    check a file name length, leading to an out- of-bounds write vulnerability. An attacker could use this to
    construct a malicious exFAT image that, when mounted and operated on, could cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2023-4273)

    Lonial Con discovered that the netfilter subsystem in the Linux kernel contained a memory leak when
    handling certain element flush operations. A local attacker could use this to expose sensitive information
    (kernel memory). (CVE-2023-4569)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6385-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40283");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2163");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-4004");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.0.0-1021-oem");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '6.0.0': {
      'oem': '6.0.0-1021'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6385-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-4269', 'CVE-2022-27672', 'CVE-2023-0458', 'CVE-2023-1075', 'CVE-2023-1076', 'CVE-2023-1206', 'CVE-2023-1380', 'CVE-2023-1611', 'CVE-2023-2002', 'CVE-2023-2162', 'CVE-2023-2163', 'CVE-2023-2235', 'CVE-2023-2269', 'CVE-2023-2898', 'CVE-2023-3090', 'CVE-2023-3141', 'CVE-2023-3220', 'CVE-2023-3390', 'CVE-2023-3609', 'CVE-2023-3610', 'CVE-2023-3611', 'CVE-2023-3776', 'CVE-2023-3777', 'CVE-2023-3863', 'CVE-2023-3995', 'CVE-2023-4004', 'CVE-2023-4015', 'CVE-2023-4128', 'CVE-2023-4194', 'CVE-2023-4273', 'CVE-2023-4569', 'CVE-2023-20593', 'CVE-2023-28328', 'CVE-2023-28466', 'CVE-2023-31436', 'CVE-2023-32269', 'CVE-2023-40283');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6385-1');
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
