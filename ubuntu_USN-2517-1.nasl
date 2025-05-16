#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2517-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81570);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2014-8133",
    "CVE-2014-8160",
    "CVE-2014-8559",
    "CVE-2014-8989",
    "CVE-2014-9419",
    "CVE-2014-9420",
    "CVE-2014-9428",
    "CVE-2014-9529",
    "CVE-2014-9584",
    "CVE-2014-9585",
    "CVE-2014-9683",
    "CVE-2014-9728",
    "CVE-2014-9729",
    "CVE-2014-9730",
    "CVE-2014-9731",
    "CVE-2015-0239"
  );
  script_bugtraq_id(
    70854,
    71154,
    71684,
    71717,
    71794,
    71847,
    71880,
    71883,
    71990,
    72061,
    72643,
    72842
  );
  script_xref(name:"USN", value:"2517-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (Utopic HWE) vulnerabilities (USN-2517-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-2517-1 advisory.

    A flaw was discovered in the Kernel Virtual Machine's (KVM) emulation of the SYSTENTER instruction when
    the guest OS does not initialize the SYSENTER MSRs. A guest OS user could exploit this flaw to cause a
    denial of service of the guest OS (crash) or potentially gain privileges on the guest OS. (CVE-2015-0239)

    Andy Lutomirski discovered an information leak in the Linux kernel's Thread Local Storage (TLS)
    implementation allowing users to bypass the espfix to obtain information that could be used to bypass the
    Address Space Layout Randomization (ASLR) protection mechanism. A local user could exploit this flaw to
    obtain potentially sensitive information from kernel memory. (CVE-2014-8133)

    A restriction bypass was discovered in iptables when conntrack rules are specified and the conntrack
    protocol handler module is not loaded into the Linux kernel. This flaw can cause the firewall rules on the
    system to be bypassed when conntrack rules are used. (CVE-2014-8160)

    A flaw was discovered with file renaming in the linux kernel. A local user could exploit this flaw to
    cause a denial of service (deadlock and system hang). (CVE-2014-8559)

    A flaw was discovered in how supplemental group memberships are handled in certain namespace scenarios. A
    local user could exploit this flaw to bypass file permission restrictions. (CVE-2014-8989)

    A flaw was discovered in how Thread Local Storage (TLS) is handled by the task switching function in the
    Linux kernel for x86_64 based machines. A local user could exploit this flaw to bypass the Address Space
    Layout Radomization (ASLR) protection mechanism. (CVE-2014-9419)

    Prasad J Pandit reported a flaw in the rock_continue function of the Linux kernel's ISO 9660 CDROM file
    system. A local user could exploit this flaw to cause a denial of service (system crash or hang).
    (CVE-2014-9420)

    A flaw was discovered in the fragment handling of the B.A.T.M.A.N. Advanced Meshing Protocol in the Linux
    kernel. A remote attacker could exploit this flaw to cause a denial of service (mesh-node system crash)
    via fragmented packets. (CVE-2014-9428)

    A race condition was discovered in the Linux kernel's key ring. A local user could cause a denial of
    service (memory corruption or panic) or possibly have unspecified impact via the keyctl commands.
    (CVE-2014-9529)

    A memory leak was discovered in the ISO 9660 CDROM file system when parsing rock ridge ER records. A local
    user could exploit this flaw to obtain sensitive information from kernel memory via a crafted iso9660
    image. (CVE-2014-9584)

    A flaw was discovered in the Address Space Layout Randomization (ASLR) of the Virtual Dynamically linked
    Shared Objects (vDSO) location. This flaw makes it easier for a local user to bypass the ASLR protection
    mechanism. (CVE-2014-9585)

    Dmitry Chernenkov discovered a buffer overflow in eCryptfs' encrypted file name decoding. A local
    unprivileged user could exploit this flaw to cause a denial of service (system crash) or potentially gain
    administrative privileges. (CVE-2014-9683)

    Carl H Lunde discovered that the UDF file system (CONFIG_UDF_FS) failed to verify symlink size info. A
    local attacker, who is able to mount a malicous UDF file system image, could exploit this flaw to cause a
    denial of service (system crash) or possibly cause other undesired behaviors. (CVE-2014-9728)

    Carl H Lunde discovered that the UDF file system (CONFIG_UDF_FS) did not valid inode size information . A
    local attacker, who is able to mount a malicous UDF file system image, could exploit this flaw to cause a
    denial of service (system crash) or possibly cause other undesired behaviors. (CVE-2014-9729)

    Carl H Lunde discovered that the UDF file system (CONFIG_UDF_FS) did not correctly verify the component
    length for symlinks. A local attacker, who is able to mount a malicous UDF file system image, could
    exploit this flaw to cause a denial of service (system crash) or possibly cause other undesired behaviors.
    (CVE-2014-9730)

    Carl H Lunde discovered an information leak in the UDF file system (CONFIG_UDF_FS). A local attacker, who
    is able to mount a malicous UDF file system image, could exploit this flaw to read potential sensitve
    kernel memory. (CVE-2014-9731)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2517-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9529");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-8559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16.0-31-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16.0-31-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16.0-31-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16.0-31-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16.0-31-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16.0-31-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.16.0-31-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2024 Canonical, Inc. / NASL script (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    '3.16.0': {
      'generic': '3.16.0-31',
      'generic-lpae': '3.16.0-31',
      'lowlatency': '3.16.0-31',
      'powerpc-e500mc': '3.16.0-31',
      'powerpc-smp': '3.16.0-31',
      'powerpc64-emb': '3.16.0-31',
      'powerpc64-smp': '3.16.0-31'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-2517-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2014-8133', 'CVE-2014-8160', 'CVE-2014-8559', 'CVE-2014-8989', 'CVE-2014-9419', 'CVE-2014-9420', 'CVE-2014-9428', 'CVE-2014-9529', 'CVE-2014-9584', 'CVE-2014-9585', 'CVE-2014-9683', 'CVE-2014-9728', 'CVE-2014-9729', 'CVE-2014-9730', 'CVE-2014-9731', 'CVE-2015-0239');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-2517-1');
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
