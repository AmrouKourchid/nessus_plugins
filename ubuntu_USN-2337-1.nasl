#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2337-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77492);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2014-0155",
    "CVE-2014-0181",
    "CVE-2014-0206",
    "CVE-2014-4014",
    "CVE-2014-4027",
    "CVE-2014-4171",
    "CVE-2014-4508",
    "CVE-2014-4652",
    "CVE-2014-4653",
    "CVE-2014-4654",
    "CVE-2014-4655",
    "CVE-2014-4656",
    "CVE-2014-4667",
    "CVE-2014-5045"
  );
  script_bugtraq_id(
    66688,
    67034,
    67985,
    67988,
    68126,
    68157,
    68162,
    68163,
    68164,
    68170,
    68176,
    68224,
    68862
  );
  script_xref(name:"USN", value:"2337-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-2337-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-2337-1 advisory.

    A flaw was discovered in the Linux kernel virtual machine's (kvm) validation of interrupt requests (irq).
    A guest OS user could exploit this flaw to cause a denial of service (host OS crash). (CVE-2014-0155)

    Andy Lutomirski discovered a flaw in the authorization of netlink socket operations when a socket is
    passed to a process of more privilege. A local user could exploit this flaw to bypass access restrictions
    by having a privileged executable do something it was not intended to do. (CVE-2014-0181)

    An information leak was discovered in the Linux kernels aio_read_events_ring function. A local user could
    exploit this flaw to obtain potentially sensitive information from kernel memory. (CVE-2014-0206)

    A flaw was discovered in the Linux kernel's implementation of user namespaces with respect to inode
    permissions. A local user could exploit this flaw by creating a user namespace to gain administrative
    privileges. (CVE-2014-4014)

    An information leak was discovered in the rd_mcp backend of the iSCSI target subsystem in the Linux
    kernel. A local user could exploit this flaw to obtain sensitive information from ramdisk_mcp memory by
    leveraging access to a SCSI initiator. (CVE-2014-4027)

    Sasha Levin reported an issue with the Linux kernel's shared memory subsystem when used with range
    notifications and hole punching. A local user could exploit this flaw to cause a denial of service.
    (CVE-2014-4171)

    Toralf Frster reported an error in the Linux kernels syscall auditing on 32 bit x86 platforms. A local
    user could exploit this flaw to cause a denial of service (OOPS and system crash). (CVE-2014-4508)

    An information leak was discovered in the control implemenation of the Advanced Linux Sound Architecture
    (ALSA) subsystem in the Linux kernel. A local user could exploit this flaw to obtain sensitive information
    from kernel memory. (CVE-2014-4652)

    A use-after-free flaw was discovered in the Advanced Linux Sound Architecture (ALSA) control
    implementation of the Linux kernel. A local user could exploit this flaw to cause a denial of service
    (system crash). (CVE-2014-4653)

    A authorization bug was discovered with the snd_ctl_elem_add function of the Advanced Linux Sound
    Architecture (ALSA) in the Linux kernel. A local user could exploit his bug to cause a denial of service
    (remove kernel controls). (CVE-2014-4654)

    A flaw discovered in how the snd_ctl_elem function of the Advanced Linux Sound Architecture (ALSA) handled
    a reference count. A local user could exploit this flaw to cause a denial of service (integer overflow and
    limit bypass). (CVE-2014-4655)

    An integer overflow flaw was discovered in the control implementation of the Advanced Linux Sound
    Architecture (ALSA). A local user could exploit this flaw to cause a denial of service (system crash).
    (CVE-2014-4656)

    An integer underflow flaw was discovered in the Linux kernel's handling of the backlog value for certain
    SCTP packets. A remote attacker could exploit this flaw to cause a denial of service (socket outage) via a
    crafted SCTP packet. (CVE-2014-4667)

    Vasily Averin discover a reference count flaw during attempts to umount in conjunction with a symlink. A
    local user could exploit this flaw to cause a denial of service (memory consumption or use after free) or
    possibly have other unspecified impact. (CVE-2014-5045)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2337-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-5045");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0181");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-35-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-35-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-35-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-35-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-35-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-35-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-35-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-35-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2024 Canonical, Inc. / NASL script (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '3.13.0-35',
      'generic-lpae': '3.13.0-35',
      'lowlatency': '3.13.0-35',
      'powerpc-e500': '3.13.0-35',
      'powerpc-e500mc': '3.13.0-35',
      'powerpc-smp': '3.13.0-35',
      'powerpc64-emb': '3.13.0-35',
      'powerpc64-smp': '3.13.0-35'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-2337-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2014-0155', 'CVE-2014-0181', 'CVE-2014-0206', 'CVE-2014-4014', 'CVE-2014-4027', 'CVE-2014-4171', 'CVE-2014-4508', 'CVE-2014-4652', 'CVE-2014-4653', 'CVE-2014-4654', 'CVE-2014-4655', 'CVE-2014-4656', 'CVE-2014-4667', 'CVE-2014-5045');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-2337-1');
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
