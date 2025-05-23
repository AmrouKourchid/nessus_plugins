#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:1620.
##

include('compat.inc');

if (description)
{
  script_id(184755);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2020-12362", "CVE-2020-12363", "CVE-2020-12364");
  script_xref(name:"RLSA", value:"2021:1620");

  script_name(english:"Rocky Linux 8 : linux-firmware (RLSA-2021:1620)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:1620 advisory.

  - Integer overflow in the firmware for some Intel(R) Graphics Drivers for Windows * before version
    26.20.100.7212 and before Linux kernel version 5.5 may allow a privileged user to potentially enable an
    escalation of privilege via local access. (CVE-2020-12362)

  - Improper input validation in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and
    before Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of service via
    local access. (CVE-2020-12363)

  - Null pointer reference in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and
    before version Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of
    service via local access. (CVE-2020-12364)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:1620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1918613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1930246");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12362");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libertas-sd8686-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libertas-sd8787-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libertas-usb8388-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libertas-usb8388-olpc-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'iwl100-firmware-39.31.5.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl1000-firmware-39.31.5.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'iwl105-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl135-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl2000-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl2030-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl3160-firmware-25.30.13.0-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'iwl3945-firmware-15.32.2.9-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl4965-firmware-228.61.2.24-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl5000-firmware-8.83.5.1_1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl5150-firmware-8.24.2.2-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000-firmware-9.221.4.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000g2a-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000g2b-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6050-firmware-41.28.5.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl7260-firmware-25.30.13.0-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libertas-sd8686-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libertas-sd8787-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libertas-usb8388-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'libertas-usb8388-olpc-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'linux-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc');
}
