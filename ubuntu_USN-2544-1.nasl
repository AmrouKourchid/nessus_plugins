#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2544-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82071);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2013-7421",
    "CVE-2014-7822",
    "CVE-2014-9644",
    "CVE-2014-9728",
    "CVE-2014-9729",
    "CVE-2014-9730",
    "CVE-2014-9731",
    "CVE-2015-0274"
  );
  script_bugtraq_id(72320, 72322, 73156);
  script_xref(name:"USN", value:"2544-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-2544-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-2544-1 advisory.

    Eric Windisch discovered flaw in how the Linux kernel's XFS file system replaces remote attributes. A
    local access with access to an XFS file system could exploit this flaw to escalate their privileges.
    (CVE-2015-0274)

    A flaw was discovered in the automatic loading of modules in the crypto subsystem of the Linux kernel. A
    local user could exploit this flaw to load installed kernel modules, increasing the attack surface and
    potentially using this to gain administrative privileges. (CVE-2013-7421)

    The Linux kernel's splice system call did not correctly validate its parameters. A local, unprivileged
    user could exploit this flaw to cause a denial of service (system crash). (CVE-2014-7822)

    A flaw was discovered in the crypto subsystem when screening module names for automatic module loading if
    the name contained a valid crypto module name, eg. vfat(aes). A local user could exploit this flaw to load
    installed kernel modules, increasing the attack surface and potentially using this to gain administrative
    privileges. (CVE-2014-9644)

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
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2544-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0274");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-9730");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-48-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-48-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-48-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-48-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-48-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-48-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-48-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-48-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2015-2020 Canonical, Inc. / NASL script (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '3.13.0-48',
      'generic-lpae': '3.13.0-48',
      'lowlatency': '3.13.0-48',
      'powerpc-e500': '3.13.0-48',
      'powerpc-e500mc': '3.13.0-48',
      'powerpc-smp': '3.13.0-48',
      'powerpc64-emb': '3.13.0-48',
      'powerpc64-smp': '3.13.0-48'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-2544-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2013-7421', 'CVE-2014-7822', 'CVE-2014-9644', 'CVE-2014-9728', 'CVE-2014-9729', 'CVE-2014-9730', 'CVE-2014-9731', 'CVE-2015-0274');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-2544-1');
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
