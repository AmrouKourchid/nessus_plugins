#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4948-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149407);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2021-3483",
    "CVE-2021-3489",
    "CVE-2021-3490",
    "CVE-2021-3491",
    "CVE-2021-28688",
    "CVE-2021-28951",
    "CVE-2021-28952",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-28972",
    "CVE-2021-29264",
    "CVE-2021-29266",
    "CVE-2021-29646",
    "CVE-2021-29647",
    "CVE-2021-29649",
    "CVE-2021-29650",
    "CVE-2021-29657",
    "CVE-2021-31916"
  );
  script_xref(name:"USN", value:"4948-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (OEM) vulnerabilities (USN-4948-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4948-1 advisory.

    Ryota Shiga discovered that the eBPF implementation in the Linux kernel did not properly verify that a BPF
    program only reserved as much memory for a ring buffer as was allocated. A local attacker could use this
    to cause a denial of service (system crash) or execute arbitrary code. (CVE-2021-3489)

    Manfred Paul discovered that the eBPF implementation in the Linux kernel did not properly track bounds on
    bitwise operations. A local attacker could use this to cause a denial of service (system crash) or execute
    arbitrary code. (CVE-2021-3490)

    Billy Jheng Bing-Jhong discovered that the io_uring implementation of the Linux kernel did not properly
    enforce the MAX_RW_COUNT limit in some situations. A local attacker could use this to cause a denial of
    service (system crash) or execute arbitrary code. (CVE-2021-3491)

    Kiyin () discovered that the NFC LLCP protocol implementation in the Linux kernel contained a
    reference counting error. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2020-25670)

    Kiyin () discovered that the NFC LLCP protocol implementation in the Linux kernel did not properly
    deallocate memory in certain error situations. A local attacker could use this to cause a denial of
    service (memory exhaustion). (CVE-2020-25671, CVE-2020-25672)

    It was discovered that the Xen paravirtualization backend in the Linux kernel did not properly deallocate
    memory in some situations. A local attacker could use this to cause a denial of service (memory
    exhaustion). (CVE-2021-28688)

    It was discovered that the io_uring subsystem in the Linux kernel contained a race condition leading to a
    deadlock condition. A local attacker could use this to cause a denial of service. (CVE-2021-28951)

    John Stultz discovered that the audio driver for Qualcomm SDM845 systems in the Linux kernel did not
    properly validate port ID numbers. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2021-28952)

    Zygo Blaxell discovered that the btrfs file system implementation in the Linux kernel contained a race
    condition during certain cloning operations. A local attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2021-28964)

    Vince Weaver discovered that the perf subsystem in the Linux kernel did not properly handle certain PEBS
    records properly for some Intel Haswell processors. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2021-28971)

    It was discovered that the RPA PCI Hotplug driver implementation in the Linux kernel did not properly
    handle device name writes via sysfs, leading to a buffer overflow. A privileged attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2021-28972)

    It was discovered that the Freescale Gianfar Ethernet driver for the Linux kernel did not properly handle
    receive queue overrun when jumbo frames were enabled in some situations. An attacker could use this to
    cause a denial of service (system crash). (CVE-2021-29264)

    It was discovered that the vDPA backend virtio driver in the Linux kernel contained a use-after-free
    vulnerability. An attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2021-29266)

    It was discovered that the TIPC protocol implementation in the Linux kernel did not properly validate
    passed encryption key sizes. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2021-29646)

    It was discovered that the Qualcomm IPC router implementation in the Linux kernel did not properly
    initialize memory passed to user space. A local attacker could use this to expose sensitive information
    (kernel memory). (CVE-2021-29647)

    It was discovered that the BPF user mode driver implementation in the Linux kernel did not properly
    deallocate memory in some situations. A local attacker could use this to cause a denial of service (memory
    exhaustion). (CVE-2021-29649)

    It was discovered that a race condition existed in the netfilter subsystem of the Linux kernel when
    replacing tables. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2021-29650)

    Felix Wilhelm discovered that the KVM implementation in the Linux kernel for AMD processors contained race
    conditions on nested VMCB controls. A local attacker in a guest vm could possibly use this to gain
    elevated privileges. (CVE-2021-29657)

    Dan Carpenter discovered that the block device manager (dm) implementation in the Linux kernel contained a
    buffer overflow in the ioctl for listing devices. A privileged local attacker could use this to cause a
    denial of service (system crash). (CVE-2021-31916)

     discovered that the IEEE 1394 (Firewire) nosy packet sniffer driver in the Linux kernel did not
    properly perform reference counting in some situations, leading to a use-after-free vulnerability. A local
    attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2021-3483)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4948-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3491");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux eBPF ALU32 32-bit Invalid Bounds Tracking LPE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.10.0-1026-oem");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    '5.10.0': {
      'oem': '5.10.0-1026'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4948-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-25670', 'CVE-2020-25671', 'CVE-2020-25672', 'CVE-2021-3483', 'CVE-2021-3489', 'CVE-2021-3490', 'CVE-2021-3491', 'CVE-2021-28688', 'CVE-2021-28951', 'CVE-2021-28952', 'CVE-2021-28964', 'CVE-2021-28971', 'CVE-2021-28972', 'CVE-2021-29264', 'CVE-2021-29266', 'CVE-2021-29646', 'CVE-2021-29647', 'CVE-2021-29649', 'CVE-2021-29650', 'CVE-2021-29657', 'CVE-2021-31916');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4948-1');
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
