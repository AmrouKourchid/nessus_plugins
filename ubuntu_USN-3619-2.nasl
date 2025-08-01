#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3619-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108878);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-0861",
    "CVE-2017-1000407",
    "CVE-2017-11472",
    "CVE-2017-15129",
    "CVE-2017-16528",
    "CVE-2017-16532",
    "CVE-2017-16536",
    "CVE-2017-16537",
    "CVE-2017-16645",
    "CVE-2017-16646",
    "CVE-2017-16649",
    "CVE-2017-16650",
    "CVE-2017-16911",
    "CVE-2017-16912",
    "CVE-2017-16913",
    "CVE-2017-16914",
    "CVE-2017-16994",
    "CVE-2017-16995",
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-17450",
    "CVE-2017-17558",
    "CVE-2017-17741",
    "CVE-2017-17805",
    "CVE-2017-17806",
    "CVE-2017-17807",
    "CVE-2017-17862",
    "CVE-2017-18075",
    "CVE-2017-18203",
    "CVE-2017-18204",
    "CVE-2017-18208",
    "CVE-2017-7518",
    "CVE-2018-1000026",
    "CVE-2018-5332",
    "CVE-2018-5333",
    "CVE-2018-5344",
    "CVE-2018-6927",
    "CVE-2018-7492",
    "CVE-2018-8043"
  );
  script_xref(name:"USN", value:"3619-2");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (Xenial HWE) vulnerabilities (USN-3619-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3619-2 advisory.

    USN-3619-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04 LTS. This update provides the
    corresponding updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
    14.04 LTS.

    Jann Horn discovered that the Berkeley Packet Filter (BPF) implementation in the Linux kernel improperly
    performed sign extension in some situations. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2017-16995)

    It was discovered that a race condition leading to a use-after-free vulnerability existed in the ALSA PCM
    subsystem of the Linux kernel. A local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2017-0861)

    It was discovered that the KVM implementation in the Linux kernel allowed passthrough of the diagnostic
    I/O port 0x80. An attacker in a guest VM could use this to cause a denial of service (system crash) in the
    host OS. (CVE-2017-1000407)

    It was discovered that an information disclosure vulnerability existed in the ACPI implementation of the
    Linux kernel. A local attacker could use this to expose sensitive information (kernel memory addresses).
    (CVE-2017-11472)

    It was discovered that a use-after-free vulnerability existed in the network namespaces implementation in
    the Linux kernel. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2017-15129)

    It was discovered that the Advanced Linux Sound Architecture (ALSA) subsystem in the Linux kernel
    contained a use-after-free when handling device removal. A physically proximate attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2017-16528)

    Andrey Konovalov discovered that the usbtest device driver in the Linux kernel did not properly validate
    endpoint metadata. A physically proximate attacker could use this to cause a denial of service (system
    crash). (CVE-2017-16532)

    Andrey Konovalov discovered that the Conexant cx231xx USB video capture driver in the Linux kernel did not
    properly validate interface descriptors. A physically proximate attacker could use this to cause a denial
    of service (system crash). (CVE-2017-16536)

    Andrey Konovalov discovered that the SoundGraph iMON USB driver in the Linux kernel did not properly
    validate device metadata. A physically proximate attacker could use this to cause a denial of service
    (system crash). (CVE-2017-16537)

    Andrey Konovalov discovered that the IMS Passenger Control Unit USB driver in the Linux kernel did not
    properly validate device descriptors. A physically proximate attacker could use this to cause a denial of
    service (system crash). (CVE-2017-16645)

    Andrey Konovalov discovered that the DiBcom DiB0700 USB DVB driver in the Linux kernel did not properly
    handle detach events. A physically proximate attacker could use this to cause a denial of service (system
    crash). (CVE-2017-16646)

    Andrey Konovalov discovered that the CDC USB Ethernet driver did not properly validate device descriptors.
    A physically proximate attacker could use this to cause a denial of service (system crash).
    (CVE-2017-16649)

    Andrey Konovalov discovered that the QMI WWAN USB driver did not properly validate device descriptors. A
    physically proximate attacker could use this to cause a denial of service (system crash). (CVE-2017-16650)

    It was discovered that the USB Virtual Host Controller Interface (VHCI) driver in the Linux kernel
    contained an information disclosure vulnerability. A physically proximate attacker could use this to
    expose sensitive information (kernel memory). (CVE-2017-16911)

    It was discovered that the USB over IP implementation in the Linux kernel did not validate endpoint
    numbers. A remote attacker could use this to cause a denial of service (system crash). (CVE-2017-16912)

    It was discovered that the USB over IP implementation in the Linux kernel did not properly validate
    CMD_SUBMIT packets. A remote attacker could use this to cause a denial of service (excessive memory
    consumption). (CVE-2017-16913)

    It was discovered that the USB over IP implementation in the Linux kernel contained a NULL pointer
    dereference error. A remote attacker could use this to cause a denial of service (system crash).
    (CVE-2017-16914)

    It was discovered that the HugeTLB component of the Linux kernel did not properly handle holes in hugetlb
    ranges. A local attacker could use this to expose sensitive information (kernel memory). (CVE-2017-16994)

    It was discovered that the netfilter component of the Linux did not properly restrict access to the
    connection tracking helpers list. A local attacker could use this to bypass intended access restrictions.
    (CVE-2017-17448)

    It was discovered that the netlink subsystem in the Linux kernel did not properly restrict observations of
    netlink messages to the appropriate net namespace. A local attacker could use this to expose sensitive
    information (kernel netlink traffic). (CVE-2017-17449)

    It was discovered that the netfilter passive OS fingerprinting (xt_osf) module did not properly perform
    access control checks. A local attacker could improperly modify the system-wide OS fingerprint list.
    (CVE-2017-17450)

    It was discovered that the core USB subsystem in the Linux kernel did not validate the number of
    configurations and interfaces in a device. A physically proximate attacker could use this to cause a
    denial of service (system crash). (CVE-2017-17558)

    Dmitry Vyukov discovered that the KVM implementation in the Linux kernel contained an out-of-bounds read
    when handling memory-mapped I/O. A local attacker could use this to expose sensitive information.
    (CVE-2017-17741)

    It was discovered that the Salsa20 encryption algorithm implementations in the Linux kernel did not
    properly handle zero-length inputs. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2017-17805)

    It was discovered that the HMAC implementation did not validate the state of the underlying cryptographic
    hash algorithm. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2017-17806)

    It was discovered that the keyring implementation in the Linux kernel did not properly check permissions
    when a key request was performed on a task's default keyring. A local attacker could use this to add keys
    to unauthorized keyrings. (CVE-2017-17807)

    Alexei Starovoitov discovered that the Berkeley Packet Filter (BPF) implementation in the Linux kernel
    contained a branch-pruning logic issue around unreachable code. A local attacker could use this to cause a
    denial of service. (CVE-2017-17862)

    It was discovered that the parallel cryptography component of the Linux kernel incorrectly freed kernel
    memory. A local attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2017-18075)

    It was discovered that a race condition existed in the Device Mapper component of the Linux kernel. A
    local attacker could use this to cause a denial of service (system crash). (CVE-2017-18203)

    It was discovered that a race condition existed in the OCFS2 file system implementation in the Linux
    kernel. A local attacker could use this to cause a denial of service (kernel deadlock). (CVE-2017-18204)

    It was discovered that an infinite loop could occur in the madvise(2) implementation in the Linux kernel
    in certain circumstances. A local attacker could use this to cause a denial of service (system hang).
    (CVE-2017-18208)

    Andy Lutomirski discovered that the KVM implementation in the Linux kernel was vulnerable to a debug
    exception error when single-stepping through a syscall. A local attacker in a non-Linux guest vm could
    possibly use this to gain administrative privileges in the guest vm. (CVE-2017-7518)

    It was discovered that the Broadcom NetXtremeII ethernet driver in the Linux kernel did not properly
    validate Generic Segment Offload (GSO) packet sizes. An attacker could use this to cause a denial of
    service (interface unavailability). (CVE-2018-1000026)

    It was discovered that the Reliable Datagram Socket (RDS) implementation in the Linux kernel contained an
    out-of-bounds write during RDMA page allocation. An attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2018-5332)

    Mohamed Ghannam discovered a null pointer dereference in the RDS (Reliable Datagram Sockets) protocol
    implementation of the Linux kernel. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2018-5333)

     discovered that a race condition existed in loop block device implementation in the Linux
    kernel. A local attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2018-5344)

    It was discovered that an integer overflow error existed in the futex implementation in the Linux kernel.
    A local attacker could use this to cause a denial of service (system crash). (CVE-2018-6927)

    It was discovered that a NULL pointer dereference existed in the RDS (Reliable Datagram Sockets) protocol
    implementation in the Linux kernel. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2018-7492)

    It was discovered that the Broadcom UniMAC MDIO bus controller driver in the Linux kernel did not properly
    validate device resources. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2018-8043)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3619-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5332");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BPF Sign Extension Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1016-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-119-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-119-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-119-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-119-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-119-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-119-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-119-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2018-2024 Canonical, Inc. / NASL script (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '14.04': {
    '4.4.0': {
      'generic': '4.4.0-119',
      'generic-lpae': '4.4.0-119',
      'lowlatency': '4.4.0-119',
      'powerpc-e500mc': '4.4.0-119',
      'powerpc-smp': '4.4.0-119',
      'powerpc64-emb': '4.4.0-119',
      'powerpc64-smp': '4.4.0-119',
      'aws': '4.4.0-1016'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3619-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2017-0861', 'CVE-2017-7518', 'CVE-2017-11472', 'CVE-2017-15129', 'CVE-2017-16528', 'CVE-2017-16532', 'CVE-2017-16536', 'CVE-2017-16537', 'CVE-2017-16645', 'CVE-2017-16646', 'CVE-2017-16649', 'CVE-2017-16650', 'CVE-2017-16911', 'CVE-2017-16912', 'CVE-2017-16913', 'CVE-2017-16914', 'CVE-2017-16994', 'CVE-2017-16995', 'CVE-2017-17448', 'CVE-2017-17449', 'CVE-2017-17450', 'CVE-2017-17558', 'CVE-2017-17741', 'CVE-2017-17805', 'CVE-2017-17806', 'CVE-2017-17807', 'CVE-2017-17862', 'CVE-2017-18075', 'CVE-2017-18203', 'CVE-2017-18204', 'CVE-2017-18208', 'CVE-2017-1000407', 'CVE-2018-5332', 'CVE-2018-5333', 'CVE-2018-5344', 'CVE-2018-6927', 'CVE-2018-7492', 'CVE-2018-8043', 'CVE-2018-1000026');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3619-2');
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
