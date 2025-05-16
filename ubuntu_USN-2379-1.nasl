#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2379-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78259);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-3181",
    "CVE-2014-3184",
    "CVE-2014-3185",
    "CVE-2014-3186",
    "CVE-2014-3631",
    "CVE-2014-6410",
    "CVE-2014-6416",
    "CVE-2014-6417",
    "CVE-2014-6418"
  );
  script_bugtraq_id(
    69763,
    69768,
    69779,
    69781,
    69799,
    69805,
    70095
  );
  script_xref(name:"USN", value:"2379-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-2379-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-2379-1 advisory.

    Steven Vittitoe reported multiple stack buffer overflows in Linux kernel's magicmouse HID driver. A
    physically proximate attacker could exploit this flaw to cause a denial of service (system crash) or
    possibly execute arbitrary code via specially crafted devices. (CVE-2014-3181)

    Ben Hawkes reported some off by one errors for report descriptors in the Linux kernel's HID stack. A
    physically proximate attacker could exploit these flaws to cause a denial of service (out-of-bounds write)
    via a specially crafted device. (CVE-2014-3184)

    Several bounds check flaws allowing for buffer overflows were discovered in the Linux kernel's Whiteheat
    USB serial driver. A physically proximate attacker could exploit these flaws to cause a denial of service
    (system crash) via a specially crafted device. (CVE-2014-3185)

    Steven Vittitoe reported a buffer overflow in the Linux kernel's PicoLCD HID device driver. A physically
    proximate attacker could exploit this flaw to cause a denial of service (system crash) or possibly execute
    arbitrary code via a specially craft device. (CVE-2014-3186)

    A flaw was discovered in the Linux kernel's associative-array garbage collection implementation. A local
    user could exploit this flaw to cause a denial of service (system crash) or possibly have other
    unspecified impact by using keyctl operations. (CVE-2014-3631)

    A flaw was discovered in the Linux kernel's UDF filesystem (used on some CD-ROMs and DVDs) when processing
    indirect ICBs. An attacker who can cause CD, DVD or image file with a specially crafted inode to be
    mounted can cause a denial of service (infinite loop or stack consumption). (CVE-2014-6410)

    James Eckersall discovered a buffer overflow in the Ceph filesystem in the Linux kernel. A remote attacker
    could exploit this flaw to cause a denial of service (memory consumption and panic) or possibly have other
    unspecified impact via a long unencrypted auth ticket. (CVE-2014-6416)

    James Eckersall discovered a flaw in the handling of memory allocation failures in the Ceph filesystem. A
    remote attacker could exploit this flaw to cause a denial of service (system crash) or possibly have
    unspecified other impact. (CVE-2014-6417)

    James Eckersall discovered a flaw in how the Ceph filesystem validates auth replies. A remote attacker
    could exploit this flaw to cause a denial of service (system crash) or possibly have other unspecified
    impact. (CVE-2014-6418)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2379-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3631");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-6416");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-37-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-37-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-37-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-37-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-37-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-37-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-37-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-37-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '3.13.0-37',
      'generic-lpae': '3.13.0-37',
      'lowlatency': '3.13.0-37',
      'powerpc-e500': '3.13.0-37',
      'powerpc-e500mc': '3.13.0-37',
      'powerpc-smp': '3.13.0-37',
      'powerpc64-emb': '3.13.0-37',
      'powerpc64-smp': '3.13.0-37'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-2379-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2014-3181', 'CVE-2014-3184', 'CVE-2014-3185', 'CVE-2014-3186', 'CVE-2014-3631', 'CVE-2014-6410', 'CVE-2014-6416', 'CVE-2014-6417', 'CVE-2014-6418');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-2379-1');
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
