#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4186-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130966);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-12207",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-11135",
    "CVE-2019-15098",
    "CVE-2019-16746",
    "CVE-2019-17052",
    "CVE-2019-17053",
    "CVE-2019-17054",
    "CVE-2019-17055",
    "CVE-2019-17056",
    "CVE-2019-17666",
    "CVE-2019-2215"
  );
  script_xref(name:"USN", value:"4186-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-4186-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4186-1 advisory.

    Stephan van Schaik, Alyssa Milburn, Sebastian sterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos,
    Cristiano Giuffrida, Giorgi Maisuradze, Moritz Lipp, Michael Schwarz, Daniel Gruss, and Jo Van Bulck
    discovered that Intel processors using Transactional Synchronization Extensions (TSX) could expose memory
    contents previously stored in microarchitectural buffers to a malicious process that is executing on the
    same CPU core. A local attacker could use this to expose sensitive information. (CVE-2019-11135)

    It was discovered that the Intel i915 graphics chipsets allowed userspace to modify page table entries via
    writes to MMIO from the Blitter Command Streamer and expose kernel memory information. A local attacker
    could use this to expose sensitive information or possibly elevate privileges. (CVE-2019-0155)

    Deepak Gupta discovered that on certain Intel processors, the Linux kernel did not properly perform
    invalidation on page table updates by virtual guest operating systems. A local attacker in a guest VM
    could use this to cause a denial of service (host system crash). (CVE-2018-12207)

    It was discovered that the Intel i915 graphics chipsets could cause a system hang when userspace performed
    a read from GT memory mapped input output (MMIO) when the product is in certain low power states. A local
    attacker could use this to cause a denial of service. (CVE-2019-0154)

    Hui Peng discovered that the Atheros AR6004 USB Wi-Fi device driver for the Linux kernel did not properly
    validate endpoint descriptors returned by the device. A physically proximate attacker could use this to
    cause a denial of service (system crash). (CVE-2019-15098)

    It was discovered that a buffer overflow existed in the 802.11 Wi-Fi configuration interface for the Linux
    kernel when handling beacon settings. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2019-16746)

    Ori Nimron discovered that the AX25 network protocol implementation in the Linux kernel did not properly
    perform permissions checks. A local attacker could use this to create a raw socket. (CVE-2019-17052)

    Ori Nimron discovered that the IEEE 802.15.4 Low-Rate Wireless network protocol implementation in the
    Linux kernel did not properly perform permissions checks. A local attacker could use this to create a raw
    socket. (CVE-2019-17053)

    Ori Nimron discovered that the Appletalk network protocol implementation in the Linux kernel did not
    properly perform permissions checks. A local attacker could use this to create a raw socket.
    (CVE-2019-17054)

    Ori Nimron discovered that the modular ISDN network protocol implementation in the Linux kernel did not
    properly perform permissions checks. A local attacker could use this to create a raw socket.
    (CVE-2019-17055)

    Ori Nimron discovered that the Near field Communication (NFC) network protocol implementation in the Linux
    kernel did not properly perform permissions checks. A local attacker could use this to create a raw
    socket. (CVE-2019-17056)

    Nico Waisman discovered that a buffer overflow existed in the Realtek Wi-Fi driver for the Linux kernel
    when handling Notice of Absence frames. A physically proximate attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2019-17666)

    Maddie Stone discovered that the Binder IPC Driver implementation in the Linux kernel contained a use-
    after-free vulnerability. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2019-2215)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4186-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16746");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android Binder Use-After-Free Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1062-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1098-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-168-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-168-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-168-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-168-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-168-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-168-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-168-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '4.4.0-168',
      'generic-lpae': '4.4.0-168',
      'lowlatency': '4.4.0-168',
      'powerpc-e500mc': '4.4.0-168',
      'powerpc-smp': '4.4.0-168',
      'powerpc64-emb': '4.4.0-168',
      'powerpc64-smp': '4.4.0-168',
      'kvm': '4.4.0-1062',
      'aws': '4.4.0-1098'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4186-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2018-12207', 'CVE-2019-0154', 'CVE-2019-0155', 'CVE-2019-2215', 'CVE-2019-11135', 'CVE-2019-15098', 'CVE-2019-16746', 'CVE-2019-17052', 'CVE-2019-17053', 'CVE-2019-17054', 'CVE-2019-17055', 'CVE-2019-17056', 'CVE-2019-17666');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4186-1');
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
