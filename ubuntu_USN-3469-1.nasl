#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3469-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104320);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-10911",
    "CVE-2017-12153",
    "CVE-2017-12154",
    "CVE-2017-12192",
    "CVE-2017-14051",
    "CVE-2017-14156",
    "CVE-2017-14340",
    "CVE-2017-14489",
    "CVE-2017-14991",
    "CVE-2017-15537",
    "CVE-2017-9984",
    "CVE-2017-9985"
  );
  script_xref(name:"USN", value:"3469-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-3469-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3469-1 advisory.

    Anthony Perard discovered that the Xen virtual block driver did not properly initialize some data
    structures before passing them to user space. A local attacker in a guest VM could use this to expose
    sensitive information from the host OS or other guest VMs. (CVE-2017-10911)

    Bo Zhang discovered that the netlink wireless configuration interface in the Linux kernel did not properly
    validate attributes when handling certain requests. A local attacker with the CAP_NET_ADMIN could use this
    to cause a denial of service (system crash). (CVE-2017-12153)

    It was discovered that the nested KVM implementation in the Linux kernel in some situations did not
    properly prevent second level guests from reading and writing the hardware CR8 register. A local attacker
    in a guest could use this to cause a denial of service (system crash).

    It was discovered that the key management subsystem in the Linux kernel did not properly restrict key
    reads on negatively instantiated keys. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2017-12192)

    It was discovered that an integer overflow existed in the sysfs interface for the QLogic 24xx+ series SCSI
    driver in the Linux kernel. A local privileged attacker could use this to cause a denial of service
    (system crash). (CVE-2017-14051)

    It was discovered that the ATI Radeon framebuffer driver in the Linux kernel did not properly initialize a
    data structure returned to user space. A local attacker could use this to expose sensitive information
    (kernel memory). (CVE-2017-14156)

    Dave Chinner discovered that the XFS filesystem did not enforce that the realtime inode flag was settable
    only on filesystems on a realtime device. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2017-14340)

    ChunYu Wang discovered that the iSCSI transport implementation in the Linux kernel did not properly
    validate data structures. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2017-14489)

    It was discovered that the generic SCSI driver in the Linux kernel did not properly initialize data
    returned to user space in some situations. A local attacker could use this to expose sensitive information
    (kernel memory). (CVE-2017-14991)

    Dmitry Vyukov discovered that the Floating Point Unit (fpu) subsystem in the Linux kernel did not properly
    handle attempts to set reserved bits in a task's extended state (xstate) area. A local attacker could use
    this to cause a denial of service (system crash). (CVE-2017-15537)

    Pengfei Wang discovered that the Turtle Beach MultiSound audio device driver in the Linux kernel contained
    race conditions when fetching from the ring-buffer. A local attacker could use this to cause a denial of
    service (infinite loop). (CVE-2017-9984, CVE-2017-9985)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3469-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9985");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1009-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1033-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1039-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1076-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1078-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-98-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-98-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-98-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-98-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-98-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-98-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-98-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2024 Canonical, Inc. / NASL script (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '16.04': {
    '4.4.0': {
      'generic': '4.4.0-98',
      'generic-lpae': '4.4.0-98',
      'lowlatency': '4.4.0-98',
      'powerpc-e500mc': '4.4.0-98',
      'powerpc-smp': '4.4.0-98',
      'powerpc64-emb': '4.4.0-98',
      'powerpc64-smp': '4.4.0-98',
      'kvm': '4.4.0-1009',
      'gke': '4.4.0-1033',
      'aws': '4.4.0-1039',
      'raspi2': '4.4.0-1076',
      'snapdragon': '4.4.0-1078'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3469-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2017-9984', 'CVE-2017-9985', 'CVE-2017-10911', 'CVE-2017-12153', 'CVE-2017-12154', 'CVE-2017-12192', 'CVE-2017-14051', 'CVE-2017-14156', 'CVE-2017-14340', 'CVE-2017-14489', 'CVE-2017-14991', 'CVE-2017-15537');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3469-1');
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
