#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2929-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89932);
  script_version("2.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2013-4312",
    "CVE-2015-7566",
    "CVE-2015-7833",
    "CVE-2016-0723",
    "CVE-2016-2384",
    "CVE-2016-2543",
    "CVE-2016-2544",
    "CVE-2016-2545",
    "CVE-2016-2546",
    "CVE-2016-2547",
    "CVE-2016-2548",
    "CVE-2016-2549",
    "CVE-2016-2782",
    "CVE-2016-3134"
  );
  script_xref(name:"USN", value:"2929-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-2929-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-2929-1 advisory.

    Ben Hawkes discovered that the Linux netfilter implementation did not correctly perform validation when
    handling IPT_SO_SET_REPLACE events. A local unprivileged attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code with administrative privileges. (CVE-2016-3134)

    It was discovered that the Linux kernel did not properly enforce rlimits for file descriptors sent over
    UNIX domain sockets. A local attacker could use this to cause a denial of service. (CVE-2013-4312)

    Ralf Spenneberg discovered that the USB driver for Clie devices in the Linux kernel did not properly
    validate the endpoints reported by the device. An attacker with physical access could cause a denial of
    service (system crash). (CVE-2015-7566)

    Ralf Spenneberg discovered that the usbvision driver in the Linux kernel did not properly validate the
    interfaces and endpoints reported by the device. An attacker with physical access could cause a denial of
    service (system crash). (CVE-2015-7833)

    It was discovered that a race condition existed in the ioctl handler for the TTY driver in the Linux
    kernel. A local attacker could use this to cause a denial of service (system crash) or expose sensitive
    information. (CVE-2016-0723)

    Andrey Konovalov discovered that the ALSA USB MIDI driver incorrectly performed a double-free. A local
    attacker with physical access could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code with administrative privileges. (CVE-2016-2384)

    Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA) framework did not verify that a
    FIFO was attached to a client before attempting to clear it. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2016-2543)

    Dmitry Vyukov discovered that a race condition existed in the Advanced Linux Sound Architecture (ALSA)
    framework between timer setup and closing of the client, resulting in a use-after-free. A local attacker
    could use this to cause a denial of service. (CVE-2016-2544)

    Dmitry Vyukov discovered a race condition in the timer handling implementation of the Advanced Linux Sound
    Architecture (ALSA) framework, resulting in a use-after-free. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2016-2545)

    Dmitry Vyukov discovered race conditions in the Advanced Linux Sound Architecture (ALSA) framework's timer
    ioctls leading to a use-after-free. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2016-2546)

    Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA) framework's handling of high
    resolution timers did not properly manage its data structures. A local attacker could use this to cause a
    denial of service (system hang or crash) or possibly execute arbitrary code. (CVE-2016-2547,
    CVE-2016-2548)

    Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA) framework's handling of high
    resolution timers could lead to a deadlock condition. A local attacker could use this to cause a denial of
    service (system hang). (CVE-2016-2549)

    Ralf Spenneberg discovered that the USB driver for Treo devices in the Linux kernel did not properly
    validate the endpoints reported by the device. An attacker with physical access could cause a denial of
    service (system crash). (CVE-2016-2782)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2929-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3134");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-83-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-83-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-83-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-83-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-83-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-83-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-83-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-83-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2020 Canonical, Inc. / NASL script (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '3.13.0-83',
      'generic-lpae': '3.13.0-83',
      'lowlatency': '3.13.0-83',
      'powerpc-e500': '3.13.0-83',
      'powerpc-e500mc': '3.13.0-83',
      'powerpc-smp': '3.13.0-83',
      'powerpc64-emb': '3.13.0-83',
      'powerpc64-smp': '3.13.0-83'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-2929-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2013-4312', 'CVE-2015-7566', 'CVE-2015-7833', 'CVE-2016-0723', 'CVE-2016-2384', 'CVE-2016-2543', 'CVE-2016-2544', 'CVE-2016-2545', 'CVE-2016-2546', 'CVE-2016-2547', 'CVE-2016-2548', 'CVE-2016-2549', 'CVE-2016-2782', 'CVE-2016-3134');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-2929-1');
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
