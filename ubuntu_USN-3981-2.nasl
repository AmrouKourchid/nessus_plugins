#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3981-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125142);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2018-16884",
    "CVE-2019-11091",
    "CVE-2019-3874",
    "CVE-2019-3882",
    "CVE-2019-9500",
    "CVE-2019-9503"
  );
  script_xref(name:"USN", value:"3981-2");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel (HWE) vulnerabilities (USN-3981-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3981-2 advisory.

    USN-3981-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04 LTS. This update provides the
    corresponding updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu 18.04 LTS for Ubuntu
    16.04 LTS and for the Linux Azure kernel for Ubuntu 14.04 LTS.

    Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Giorgi Maisuradze, Dan Horea Lutas, Andrei Lutas,
    Volodymyr Pikhur, Stephan van Schaik, Alyssa Milburn, Sebastian sterlund, Pietro Frigo, Kaveh Razavi,
    Herbert Bos, Cristiano Giuffrida, Moritz Lipp, Michael Schwarz, and Daniel Gruss discovered that memory
    previously stored in microarchitectural fill buffers of an Intel CPU core may be exposed to a malicious
    process that is executing on the same CPU core. A local attacker could use this to expose sensitive
    information. (CVE-2018-12130)

    Brandon Falk, Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Stephan van Schaik, Alyssa Milburn,
    Sebastian sterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos, and Cristiano Giuffrida discovered that
    memory previously stored in microarchitectural load ports of an Intel CPU core may be exposed to a
    malicious process that is executing on the same CPU core. A local attacker could use this to expose
    sensitive information. (CVE-2018-12127)

    Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Marina Minkin, Daniel Moghimi, Moritz Lipp, Michael
    Schwarz, Jo Van Bulck, Daniel Genkin, Daniel Gruss, Berk Sunar, Frank Piessens, and Yuval Yarom discovered
    that memory previously stored in microarchitectural store buffers of an Intel CPU core may be exposed to a
    malicious process that is executing on the same CPU core. A local attacker could use this to expose
    sensitive information. (CVE-2018-12126)

    Vasily Averin and Evgenii Shatokhin discovered that a use-after-free vulnerability existed in the NFS41+
    subsystem when multiple network namespaces are in use. A local attacker in a container could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2018-16884)

    Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Volodrmyr Pikhur, Moritz Lipp, Michael Schwarz,
    Daniel Gruss, Stephan van Schaik, Alyssa Milburn, Sebastian sterlund, Pietro Frigo, Kaveh Razavi,
    Herbert Bos, and Cristiano Giuffrida discovered that uncacheable memory previously stored in
    microarchitectural buffers of an Intel CPU core may be exposed to a malicious process that is executing on
    the same CPU core. A local attacker could use this to expose sensitive information. (CVE-2019-11091)

    Matteo Croce, Natale Vinto, and Andrea Spagnolo discovered that the cgroups subsystem of the Linux kernel
    did not properly account for SCTP socket buffers. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2019-3874)

    Alex Williamson discovered that the vfio subsystem of the Linux kernel did not properly limit DMA
    mappings. A local attacker could use this to cause a denial of service (memory exhaustion).
    (CVE-2019-3882)

    Hugues Anguelkov discovered that the Broadcom Wifi driver in the Linux kernel contained a heap buffer
    overflow. A physically proximate attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2019-9500)

    Hugues Anguelkov discovered that the Broadcom Wifi driver in the Linux kernel did not properly prevent
    remote firmware events from being processed for USB Wifi devices. A physically proximate attacker could
    use this to send firmware events to the device. (CVE-2019-9503)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3981-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9503");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1013-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1032-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1045-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-50-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-50-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-50-lowlatency");
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
    '4.15.0': {
      'generic': '4.15.0-50',
      'generic-lpae': '4.15.0-50',
      'lowlatency': '4.15.0-50',
      'oracle': '4.15.0-1013',
      'gcp': '4.15.0-1032',
      'azure': '4.15.0-1045'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3981-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2018-12126', 'CVE-2018-12127', 'CVE-2018-12130', 'CVE-2018-16884', 'CVE-2019-3874', 'CVE-2019-3882', 'CVE-2019-9500', 'CVE-2019-9503', 'CVE-2019-11091');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3981-2');
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
