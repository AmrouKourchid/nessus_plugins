#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6951-4. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206041);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-48674",
    "CVE-2022-48772",
    "CVE-2023-52434",
    "CVE-2023-52585",
    "CVE-2023-52752",
    "CVE-2023-52882",
    "CVE-2024-26886",
    "CVE-2024-27019",
    "CVE-2024-27398",
    "CVE-2024-27399",
    "CVE-2024-27401",
    "CVE-2024-31076",
    "CVE-2024-33621",
    "CVE-2024-35947",
    "CVE-2024-35976",
    "CVE-2024-36014",
    "CVE-2024-36015",
    "CVE-2024-36017",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36902",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36919",
    "CVE-2024-36933",
    "CVE-2024-36934",
    "CVE-2024-36939",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36946",
    "CVE-2024-36950",
    "CVE-2024-36954",
    "CVE-2024-36959",
    "CVE-2024-36960",
    "CVE-2024-36964",
    "CVE-2024-36971",
    "CVE-2024-37353",
    "CVE-2024-37356",
    "CVE-2024-38381",
    "CVE-2024-38549",
    "CVE-2024-38552",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38560",
    "CVE-2024-38565",
    "CVE-2024-38567",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38582",
    "CVE-2024-38583",
    "CVE-2024-38587",
    "CVE-2024-38589",
    "CVE-2024-38596",
    "CVE-2024-38598",
    "CVE-2024-38599",
    "CVE-2024-38600",
    "CVE-2024-38601",
    "CVE-2024-38607",
    "CVE-2024-38612",
    "CVE-2024-38613",
    "CVE-2024-38615",
    "CVE-2024-38618",
    "CVE-2024-38621",
    "CVE-2024-38627",
    "CVE-2024-38633",
    "CVE-2024-38634",
    "CVE-2024-38635",
    "CVE-2024-38637",
    "CVE-2024-38659",
    "CVE-2024-38661",
    "CVE-2024-38780",
    "CVE-2024-39276",
    "CVE-2024-39292",
    "CVE-2024-39301",
    "CVE-2024-39467",
    "CVE-2024-39471",
    "CVE-2024-39475",
    "CVE-2024-39480",
    "CVE-2024-39488",
    "CVE-2024-39489",
    "CVE-2024-39493"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");
  script_xref(name:"USN", value:"6951-4");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (BlueField) vulnerabilities (USN-6951-4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6951-4 advisory.

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - M68K architecture;

    - User-Mode Linux (UML);

    - x86 architecture;

    - Accessibility subsystem;

    - Character device driver;

    - Clock framework and drivers;

    - CPU frequency scaling framework;

    - Hardware crypto device drivers;

    - Buffer Sharing and Synchronization framework;

    - FireWire subsystem;

    - GPU drivers;

    - HW tracing;

    - Macintosh device drivers;

    - Multiple devices driver;

    - Media drivers;

    - Network drivers;

    - Pin controllers subsystem;

    - S/390 drivers;

    - SCSI drivers;

    - SoundWire subsystem;

    - Greybus lights staging drivers;

    - TTY drivers;

    - Framebuffer layer;

    - Virtio drivers;

    - 9P distributed file system;

    - eCrypt file system;

    - EROFS file system;

    - Ext4 file system;

    - F2FS file system;

    - JFFS2 file system;

    - Network file system client;

    - NILFS2 file system;

    - SMB network file system;

    - Kernel debugger infrastructure;

    - IRQ subsystem;

    - Tracing infrastructure;

    - Dynamic debug library;

    - 9P file system network protocol;

    - Bluetooth subsystem;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - Netfilter;

    - NET/ROM layer;

    - NFC subsystem;

    - NSH protocol;

    - Open vSwitch;

    - Phonet protocol;

    - TIPC protocol;

    - Unix domain sockets;

    - Wireless networking;

    - eXpress Data Path;

    - XFRM subsystem;

    - ALSA framework; (CVE-2024-36934, CVE-2024-38578, CVE-2024-38600, CVE-2024-27399, CVE-2024-39276,
    CVE-2024-38596, CVE-2024-36933, CVE-2024-36919, CVE-2024-35976, CVE-2024-37356, CVE-2023-52585,
    CVE-2024-38558, CVE-2024-38560, CVE-2024-38634, CVE-2024-36959, CVE-2024-38633, CVE-2024-36886,
    CVE-2024-27398, CVE-2024-39493, CVE-2024-26886, CVE-2024-31076, CVE-2024-38559, CVE-2024-38615,
    CVE-2024-36971, CVE-2024-38627, CVE-2024-36964, CVE-2024-38780, CVE-2024-37353, CVE-2024-38621,
    CVE-2024-36883, CVE-2024-39488, CVE-2024-38661, CVE-2024-36939, CVE-2024-38589, CVE-2024-38565,
    CVE-2024-38381, CVE-2024-35947, CVE-2024-36905, CVE-2022-48772, CVE-2024-36017, CVE-2024-36946,
    CVE-2024-27401, CVE-2024-38579, CVE-2024-38612, CVE-2024-38598, CVE-2024-38635, CVE-2024-38587,
    CVE-2024-38567, CVE-2024-38549, CVE-2024-36960, CVE-2023-52752, CVE-2024-27019, CVE-2024-38601,
    CVE-2024-39489, CVE-2024-39467, CVE-2023-52882, CVE-2024-38583, CVE-2024-39480, CVE-2024-38607,
    CVE-2024-36940, CVE-2024-38659, CVE-2023-52434, CVE-2024-36015, CVE-2024-38582, CVE-2024-36950,
    CVE-2024-38552, CVE-2024-33621, CVE-2024-36954, CVE-2024-39475, CVE-2024-39301, CVE-2024-38599,
    CVE-2024-36902, CVE-2024-36286, CVE-2024-38613, CVE-2024-38637, CVE-2024-36941, CVE-2024-36014,
    CVE-2024-38618, CVE-2024-36904, CVE-2024-36270, CVE-2024-39292, CVE-2024-39471, CVE-2022-48674)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6951-4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1090-bluefield");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    '5.4.0': {
      'bluefield': '5.4.0-1090'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6951-4');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-48674', 'CVE-2022-48772', 'CVE-2023-52434', 'CVE-2023-52585', 'CVE-2023-52752', 'CVE-2023-52882', 'CVE-2024-26886', 'CVE-2024-27019', 'CVE-2024-27398', 'CVE-2024-27399', 'CVE-2024-27401', 'CVE-2024-31076', 'CVE-2024-33621', 'CVE-2024-35947', 'CVE-2024-35976', 'CVE-2024-36014', 'CVE-2024-36015', 'CVE-2024-36017', 'CVE-2024-36270', 'CVE-2024-36286', 'CVE-2024-36883', 'CVE-2024-36886', 'CVE-2024-36902', 'CVE-2024-36904', 'CVE-2024-36905', 'CVE-2024-36919', 'CVE-2024-36933', 'CVE-2024-36934', 'CVE-2024-36939', 'CVE-2024-36940', 'CVE-2024-36941', 'CVE-2024-36946', 'CVE-2024-36950', 'CVE-2024-36954', 'CVE-2024-36959', 'CVE-2024-36960', 'CVE-2024-36964', 'CVE-2024-36971', 'CVE-2024-37353', 'CVE-2024-37356', 'CVE-2024-38381', 'CVE-2024-38549', 'CVE-2024-38552', 'CVE-2024-38558', 'CVE-2024-38559', 'CVE-2024-38560', 'CVE-2024-38565', 'CVE-2024-38567', 'CVE-2024-38578', 'CVE-2024-38579', 'CVE-2024-38582', 'CVE-2024-38583', 'CVE-2024-38587', 'CVE-2024-38589', 'CVE-2024-38596', 'CVE-2024-38598', 'CVE-2024-38599', 'CVE-2024-38600', 'CVE-2024-38601', 'CVE-2024-38607', 'CVE-2024-38612', 'CVE-2024-38613', 'CVE-2024-38615', 'CVE-2024-38618', 'CVE-2024-38621', 'CVE-2024-38627', 'CVE-2024-38633', 'CVE-2024-38634', 'CVE-2024-38635', 'CVE-2024-38637', 'CVE-2024-38659', 'CVE-2024-38661', 'CVE-2024-38780', 'CVE-2024-39276', 'CVE-2024-39292', 'CVE-2024-39301', 'CVE-2024-39467', 'CVE-2024-39471', 'CVE-2024-39475', 'CVE-2024-39480', 'CVE-2024-39488', 'CVE-2024-39489', 'CVE-2024-39493');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6951-4');
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
