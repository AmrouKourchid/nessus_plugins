#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-021-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189266);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/29");

  script_cve_id(
    "CVE-2023-6377",
    "CVE-2023-6478",
    "CVE-2023-6816",
    "CVE-2024-0229",
    "CVE-2024-0408",
    "CVE-2024-0409",
    "CVE-2024-21885",
    "CVE-2024-21886"
  );

  script_name(english:"Slackware Linux 15.0 / current tigervnc  Multiple Vulnerabilities (SSA:2024-021-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to tigervnc.");
  script_set_attribute(attribute:"description", value:
"The version of tigervnc installed on the remote host is prior to 1.12.0 / 1.13.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2024-021-01 advisory.

  - A flaw was found in xorg-server. Querying or changing XKB button actions such as moving from a touchpad to
    a mouse can result in out-of-bounds memory reads and writes. This may allow local privilege escalation or
    possible remote code execution in cases where X11 forwarding is involved. (CVE-2023-6377)

  - A flaw was found in xorg-server. A specially crafted request to RRChangeProviderProperty or
    RRChangeOutputProperty can trigger an integer overflow which may lead to a disclosure of sensitive
    information. (CVE-2023-6478)

  - A flaw was found in X.Org server. Both DeviceFocusEvent and the XIQueryPointer reply contain a bit for
    each logical button currently down. Buttons can be arbitrarily mapped to any value up to 255, but the
    X.Org Server was only allocating space for the device's particular number of buttons, leading to a heap
    overflow if a bigger value was used. (CVE-2023-6816)

  - A flaw was found in the X.Org server. The GLX PBuffer code does not call the XACE hook when creating the
    buffer, leaving it unlabeled. When the client issues another request to access that resource (as with a
    GetGeometry) or when it creates another resource that needs to access that buffer, such as a GC, the
    XSELINUX code will try to use an object that was never labeled and crash because the SID is NULL.
    (CVE-2024-0408)

  - A flaw was found in the X.Org server. The cursor code in both Xephyr and Xwayland uses the wrong type of
    private at creation. It uses the cursor bits type with the cursor as private, and when initiating the
    cursor, that overwrites the XSELINUX context. (CVE-2024-0409)

  - The X.Org project reports: Both DeviceFocusEvent and the XIQueryPointer reply contain a bit
    for each logical button currently down. Buttons can be arbitrarily             mapped to any value up to
    255 but the X.Org Server was only             allocating space for the device's number of buttons,
    leading to a heap overflow if a bigger value was used. If a device has both a button class and a key class
    and             numButtons is zero, we can get an out-of-bounds write due             to event under-
    allocation in the DeliverStateNotifyEvent             function. The XISendDeviceHierarchyEvent() function
    allocates space to             store up to MAXDEVICES (256) xXIHierarchyInfo structures in info.
    If a device with a given ID was removed and a new device with             the same ID added both in the
    same operation,             the single device ID will lead to two info structures being
    written to info.             Since this case can occur for every device ID at once,             a total of
    two times MAXDEVICES info structures might be written             to the allocation, leading to a heap
    buffer overflow. The DisableDevice() function is called whenever an enabled device             is disabled
    and it moves the device from the inputInfo.devices             linked list to the inputInfo.off_devices
    linked list.             However, its link/unlink operation has an issue during the recursive
    call to DisableDevice() due to the prev pointer pointing to a             removed device.             This
    issue leads to a length mismatch between the total number of             devices and the number of device
    in the list, leading to a heap             overflow and, possibly, to local privilege escalation.
    (CVE-2024-0229, CVE-2024-21885, CVE-2024-21886)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.374309
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3795412");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected tigervnc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '1.12.0', 'product' : 'tigervnc', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.12.0', 'product' : 'tigervnc', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '5_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.13.1', 'product' : 'tigervnc', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '3', 'arch' : 'i586' },
    { 'fixed_version' : '1.13.1', 'product' : 'tigervnc', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '3', 'arch' : 'x86_64' }
];

foreach var constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
