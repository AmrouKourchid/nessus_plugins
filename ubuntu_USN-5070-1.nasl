#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5070-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153174);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/19");

  script_cve_id(
    "CVE-2020-26541",
    "CVE-2021-3612",
    "CVE-2021-3653",
    "CVE-2021-3656",
    "CVE-2021-22543",
    "CVE-2021-34693",
    "CVE-2021-38198",
    "CVE-2021-38200",
    "CVE-2021-38206",
    "CVE-2021-38207"
  );
  script_xref(name:"USN", value:"5070-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel vulnerabilities (USN-5070-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5070-1 advisory.

    Maxim Levitsky and Paolo Bonzini discovered that the KVM hypervisor implementation for AMD processors in
    the Linux kernel allowed a guest VM to disable restrictions on VMLOAD/VMSAVE in a nested guest. An
    attacker in a guest VM could use this to read or write portions of the host's physical memory.
    (CVE-2021-3656)

    Maxim Levitsky discovered that the KVM hypervisor implementation for AMD processors in the Linux kernel
    did not properly prevent a guest VM from enabling AVIC in nested guest VMs. An attacker in a guest VM
    could use this to write to portions of the host's physical memory. (CVE-2021-3653)

    It was discovered that the Linux kernel did not properly enforce certain types of entries in the Secure
    Boot Forbidden Signature Database (aka dbx) protection mechanism. An attacker could use this to bypass
    UEFI Secure Boot restrictions. (CVE-2020-26541)

    It was discovered that the KVM hypervisor implementation in the Linux kernel did not properly perform
    reference counting in some situations, leading to a use-after-free vulnerability. An attacker who could
    start and control a VM could possibly use this to expose sensitive information or execute arbitrary code.
    (CVE-2021-22543)

    Norbert Slusarek discovered that the CAN broadcast manger (bcm) protocol implementation in the Linux
    kernel did not properly initialize memory in some situations. A local attacker could use this to expose
    sensitive information (kernel memory). (CVE-2021-34693)

    Murray McAllister discovered that the joystick device interface in the Linux kernel did not properly
    validate data passed via an ioctl(). A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code on systems with a joystick device registered. (CVE-2021-3612)

    It was discovered that the KVM hypervisor implementation in the Linux kernel did not properly compute the
    access permissions for shadow pages in some situations. A local attacker could use this to cause a denial
    of service. (CVE-2021-38198)

    It was discovered that the perf subsystem in the Linux kernel for the PowerPC architecture contained a
    null pointer dereference in some situations. An attacker could use this to cause a denial of service
    (system crash). (CVE-2021-38200)

    Ben Greear discovered that the mac80211 subsystem in the Linux kernel contained a null pointer dereference
    in some situations. A physically proximate attacker could possibly use this to cause a denial of service
    (system crash). (CVE-2021-38206)

    It was discovered that the Xilinx LL TEMAC device driver in the Linux kernel did not properly calculate
    the number of buffers to be used in certain situations. A remote attacker could use this to cause a denial
    of service (system crash). (CVE-2021-38207)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5070-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3656");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2021-22543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1015-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1017-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-1017-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-34-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-34-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-34-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.11.0-34-lowlatency");
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
    '5.11.0': {
      'generic': '5.11.0-34',
      'generic-64k': '5.11.0-34',
      'generic-lpae': '5.11.0-34',
      'lowlatency': '5.11.0-34',
      'azure': '5.11.0-1015',
      'aws': '5.11.0-1017',
      'oracle': '5.11.0-1017'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5070-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-26541', 'CVE-2021-3612', 'CVE-2021-3653', 'CVE-2021-3656', 'CVE-2021-22543', 'CVE-2021-34693', 'CVE-2021-38198', 'CVE-2021-38200', 'CVE-2021-38206', 'CVE-2021-38207');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5070-1');
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
