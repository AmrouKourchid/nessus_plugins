#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2965-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91083);
  script_version("2.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-2184",
    "CVE-2016-2185",
    "CVE-2016-2186",
    "CVE-2016-2188",
    "CVE-2016-2847",
    "CVE-2016-3136",
    "CVE-2016-3137",
    "CVE-2016-3138",
    "CVE-2016-3140",
    "CVE-2016-3156",
    "CVE-2016-3157",
    "CVE-2016-3672",
    "CVE-2016-3689",
    "CVE-2016-3951",
    "CVE-2016-3955",
    "CVE-2016-4557"
  );
  script_xref(name:"USN", value:"2965-2");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (Xenial HWE) vulnerabilities (USN-2965-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-2965-2 advisory.

    USN-2965-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04 LTS. This update provides the
    corresponding updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
    14.04 LTS.

    Jann Horn discovered that the extended Berkeley Packet Filter (eBPF) implementation in the Linux kernel
    did not properly reference count file descriptors, leading to a use-after-free. A local unprivileged
    attacker could use this to gain administrative privileges. (CVE-2016-4557)

    Ralf Spenneberg discovered that the USB sound subsystem in the Linux kernel did not properly validate USB
    device descriptors. An attacker with physical access could use this to cause a denial of service (system
    crash). (CVE-2016-2184)

    Ralf Spenneberg discovered that the ATI Wonder Remote II USB driver in the Linux kernel did not properly
    validate USB device descriptors. An attacker with physical access could use this to cause a denial of
    service (system crash). (CVE-2016-2185)

    Ralf Spenneberg discovered that the PowerMate USB driver in the Linux kernel did not properly validate USB
    device descriptors. An attacker with physical access could use this to cause a denial of service (system
    crash). (CVE-2016-2186)

    Ralf Spenneberg discovered that the I/O-Warrior USB device driver in the Linux kernel did not properly
    validate USB device descriptors. An attacker with physical access could use this to cause a denial of
    service (system crash). (CVE-2016-2188)

    It was discovered that the Linux kernel did not enforce limits on the amount of data allocated to buffer
    pipes. A local attacker could use this to cause a denial of service (resource exhaustion). (CVE-2016-2847)

    Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the MCT USB RS232 Converter device
    driver in the Linux kernel did not properly validate USB device descriptors. An attacker with physical
    access could use this to cause a denial of service (system crash). (CVE-2016-3136)

    Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the Cypress M8 USB device driver
    in the Linux kernel did not properly validate USB device descriptors. An attacker with physical access
    could use this to cause a denial of service (system crash). (CVE-2016-3137)

    Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the USB abstract device control
    driver for modems and ISDN adapters did not validate endpoint descriptors. An attacker with physical
    access could use this to cause a denial of service (system crash). (CVE-2016-3138)

    Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the Linux kernel's USB driver for
    Digi AccelePort serial converters did not properly validate USB device descriptors. An attacker with
    physical access could use this to cause a denial of service (system crash). (CVE-2016-3140)

    It was discovered that the IPv4 implementation in the Linux kernel did not perform the destruction of inet
    device objects properly. An attacker in a guest OS could use this to cause a denial of service (networking
    outage) in the host OS. (CVE-2016-3156)

    Andy Lutomirski discovered that the Linux kernel did not properly context- switch IOPL on 64-bit PV Xen
    guests. An attacker in a guest OS could use this to cause a denial of service (guest OS crash), gain
    privileges, or obtain sensitive information. (CVE-2016-3157)

    Hector Marco and Ismael Ripoll discovered that the Linux kernel would improperly disable Address Space
    Layout Randomization (ASLR) for x86 processes running in 32 bit mode if stack-consumption resource limits
    were disabled. A local attacker could use this to make it easier to exploit an existing vulnerability in a
    setuid/setgid program. (CVE-2016-3672)

    It was discovered that the Linux kernel's USB driver for IMS Passenger Control Unit devices did not
    properly validate the device's interfaces. An attacker with physical access could use this to cause a
    denial of service (system crash). (CVE-2016-3689)

    Andrey Konovalov discovered that the CDC Network Control Model USB driver in the Linux kernel did not
    cancel work events queued if a later error occurred, resulting in a use-after-free. An attacker with
    physical access could use this to cause a denial of service (system crash). (CVE-2016-3951)

    It was discovered that an out-of-bounds write could occur when handling incoming packets in the USB/IP
    implementation in the Linux kernel. A remote attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2016-3955)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2965-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3955");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BPF doubleput UAF Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-22-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-22-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-22-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-22-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-22-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-22-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-22-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2024 Canonical, Inc. / NASL script (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '4.4.0-22',
      'generic-lpae': '4.4.0-22',
      'lowlatency': '4.4.0-22',
      'powerpc-e500mc': '4.4.0-22',
      'powerpc-smp': '4.4.0-22',
      'powerpc64-emb': '4.4.0-22',
      'powerpc64-smp': '4.4.0-22'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-2965-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2016-2184', 'CVE-2016-2185', 'CVE-2016-2186', 'CVE-2016-2188', 'CVE-2016-2847', 'CVE-2016-3136', 'CVE-2016-3137', 'CVE-2016-3138', 'CVE-2016-3140', 'CVE-2016-3156', 'CVE-2016-3157', 'CVE-2016-3672', 'CVE-2016-3689', 'CVE-2016-3951', 'CVE-2016-3955', 'CVE-2016-4557');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-2965-2');
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
