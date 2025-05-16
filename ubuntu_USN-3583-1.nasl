#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3583-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(107003);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id(
    "CVE-2017-0750",
    "CVE-2017-0861",
    "CVE-2017-1000407",
    "CVE-2017-12153",
    "CVE-2017-12190",
    "CVE-2017-12192",
    "CVE-2017-14051",
    "CVE-2017-14140",
    "CVE-2017-14156",
    "CVE-2017-14489",
    "CVE-2017-15102",
    "CVE-2017-15115",
    "CVE-2017-15274",
    "CVE-2017-15868",
    "CVE-2017-16525",
    "CVE-2017-17450",
    "CVE-2017-17806",
    "CVE-2017-18017",
    "CVE-2017-5669",
    "CVE-2017-5754",
    "CVE-2017-7542",
    "CVE-2017-7889",
    "CVE-2017-8824",
    "CVE-2018-5333",
    "CVE-2018-5344"
  );
  script_xref(name:"USN", value:"3583-1");
  script_xref(name:"IAVA", value:"2018-A-0019");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-3583-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3583-1 advisory.

    It was discovered that an out-of-bounds write vulnerability existed in the Flash-Friendly File System
    (f2fs) in the Linux kernel. An attacker could construct a malicious file system that, when mounted, could
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2017-0750)

    It was discovered that a race condition leading to a use-after-free vulnerability existed in the ALSA PCM
    subsystem of the Linux kernel. A local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2017-0861)

    It was discovered that the KVM implementation in the Linux kernel allowed passthrough of the diagnostic
    I/O port 0x80. An attacker in a guest VM could use this to cause a denial of service (system crash) in the
    host OS. (CVE-2017-1000407)

    Bo Zhang discovered that the netlink wireless configuration interface in the Linux kernel did not properly
    validate attributes when handling certain requests. A local attacker with the CAP_NET_ADMIN could use this
    to cause a denial of service (system crash). (CVE-2017-12153)

    Vitaly Mayatskikh discovered that the SCSI subsystem in the Linux kernel did not properly track reference
    counts when merging buffers. A local attacker could use this to cause a denial of service (memory
    exhaustion). (CVE-2017-12190)

    It was discovered that the key management subsystem in the Linux kernel did not properly restrict key
    reads on negatively instantiated keys. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2017-12192)

    It was discovered that an integer overflow existed in the sysfs interface for the QLogic 24xx+ series SCSI
    driver in the Linux kernel. A local privileged attacker could use this to cause a denial of service
    (system crash). (CVE-2017-14051)

    Otto Ebeling discovered that the memory manager in the Linux kernel did not properly check the effective
    UID in some situations. A local attacker could use this to expose sensitive information. (CVE-2017-14140)

    It was discovered that the ATI Radeon framebuffer driver in the Linux kernel did not properly initialize a
    data structure returned to user space. A local attacker could use this to expose sensitive information
    (kernel memory). (CVE-2017-14156)

    ChunYu Wang discovered that the iSCSI transport implementation in the Linux kernel did not properly
    validate data structures. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2017-14489)

    James Patrick-Evans discovered a race condition in the LEGO USB Infrared Tower driver in the Linux kernel.
    A physically proximate attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2017-15102)

    ChunYu Wang discovered that a use-after-free vulnerability existed in the SCTP protocol implementation in
    the Linux kernel. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code, (CVE-2017-15115)

    It was discovered that the key management subsystem in the Linux kernel did not properly handle NULL
    payloads with non-zero length values. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2017-15274)

    It was discovered that the Bluebooth Network Encapsulation Protocol (BNEP) implementation in the Linux
    kernel did not validate the type of socket passed in the BNEPCONNADD ioctl(). A local attacker with the
    CAP_NET_ADMIN privilege could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2017-15868)

    Andrey Konovalov discovered a use-after-free vulnerability in the USB serial console driver in the Linux
    kernel. A physically proximate attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2017-16525)

    It was discovered that the netfilter passive OS fingerprinting (xt_osf) module did not properly perform
    access control checks. A local attacker could improperly modify the system-wide OS fingerprint list.
    (CVE-2017-17450)

    It was discovered that the HMAC implementation did not validate the state of the underlying cryptographic
    hash algorithm. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2017-17806)

    Denys Fedoryshchenko discovered a use-after-free vulnerability in the netfilter xt_TCPMSS filter of the
    Linux kernel. A remote attacker could use this to cause a denial of service (system crash).
    (CVE-2017-18017)

    Gareth Evans discovered that the shm IPC subsystem in the Linux kernel did not properly restrict mapping
    page zero. A local privileged attacker could use this to execute arbitrary code. (CVE-2017-5669)

    It was discovered that an integer overflow vulnerability existing in the IPv6 implementation in the Linux
    kernel. A local attacker could use this to cause a denial of service (infinite loop). (CVE-2017-7542)

    Tommi Rantala and Brad Spengler discovered that the memory manager in the Linux kernel did not properly
    enforce the CONFIG_STRICT_DEVMEM protection mechanism. A local attacker with access to /dev/mem could use
    this to expose sensitive information or possibly execute arbitrary code. (CVE-2017-7889)

    Mohamed Ghannam discovered a use-after-free vulnerability in the DCCP protocol implementation in the Linux
    kernel. A local attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2017-8824)

    Mohamed Ghannam discovered a null pointer dereference in the RDS (Reliable Datagram Sockets) protocol
    implementation of the Linux kernel. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2018-5333)

     discovered that a race condition existed in loop block device implementation in the Linux
    kernel. A local attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2018-5344)

    USN-3524-1 mitigated CVE-2017-5754 (Meltdown) for the amd64 architecture in Ubuntu 14.04 LTS. This update
    provides the corresponding mitigations for the ppc64el architecture.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3583-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-142-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-142-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-142-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-142-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-142-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-142-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-142-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-142-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    '3.13.0': {
      'generic': '3.13.0-142',
      'generic-lpae': '3.13.0-142',
      'lowlatency': '3.13.0-142',
      'powerpc-e500': '3.13.0-142',
      'powerpc-e500mc': '3.13.0-142',
      'powerpc-smp': '3.13.0-142',
      'powerpc64-emb': '3.13.0-142',
      'powerpc64-smp': '3.13.0-142'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3583-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2017-0750', 'CVE-2017-0861', 'CVE-2017-5669', 'CVE-2017-5754', 'CVE-2017-7542', 'CVE-2017-7889', 'CVE-2017-8824', 'CVE-2017-12153', 'CVE-2017-12190', 'CVE-2017-12192', 'CVE-2017-14051', 'CVE-2017-14140', 'CVE-2017-14156', 'CVE-2017-14489', 'CVE-2017-15102', 'CVE-2017-15115', 'CVE-2017-15274', 'CVE-2017-15868', 'CVE-2017-16525', 'CVE-2017-17450', 'CVE-2017-17806', 'CVE-2017-18017', 'CVE-2017-1000407', 'CVE-2018-5333', 'CVE-2018-5344');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3583-1');
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
