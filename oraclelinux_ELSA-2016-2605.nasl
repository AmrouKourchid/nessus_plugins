#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2605 and 
# Oracle Linux Security Advisory ELSA-2016-2605 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94724);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2016-5011");
  script_xref(name:"RHSA", value:"2016:2605");

  script_name(english:"Oracle Linux 7 : util-linux (ELSA-2016-2605)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2016-2605 advisory.

    [2.23.2-33.0.1]
    - fix Oracle bug 23001516 - backport lscpu: correct the Virtualization type on Xen DomU PV guest
    - Reviewed-by: Joe Jin <joe.jin@oracle.com>

    [2.23.2-33]
    - improve patch for #1007734 (libblkid realpaths)

    [2.23.2-32]
    - improve patch for chrt(1) deadline support #1298384
    - fix #1007734 - blkid shows devices as /dev/block/:
    - fix #1349536 - Extended partition loop in MBR partition table leads to DOS

    [2.23.2-31]
    - improve spec file for #1092520

    [2.23.2-30]
    - improve patch for chrt(1) deadline support #1298384
    - improve regression tests

    [2.23.2-29]
    - fix #1029385 - lack of non-ascii support
    - fix #1092520 - util-linux - PIE and RELRO check
    - fix #1153770 - backport lsipc
    - fix #1248003 - mount only parses <param>=<value> lines from fstab fs_spec field available from blkid
    block device
    - fix #1271850 - mount -a doesn't catch a typo in /etc/fstab and a typo in /etc/fstab can make a system
    not reboot properly
    - fix #1281839 - [RFE]Bind mounts should be handled gracefully by the operating system
    - fix #1290689 - util-linux: /bin/login does not retry getpwnam_r with larger buffers, leading to login
    failure
    - fix #1296366 - Bash completion for more(1) handles file names with spaces incorrectly
    - fix #1296521 - RHEL7: update audit event in hwclock
    - fix #1298384 - RFE: add SCHED_DEADLINE support to chrt
    - fix #1304246 - fdisk 'f' subcommand updates partition ranges wrongly
    - fix #1304426 - [rfe] /bin/su should be improved to reduce stack use
    - fix #1326615 - util-linux/lscpu: Fix model and model name on Power Systems
    - fix #1327886 - Backport blkdiscard's '-z' flag to RHEL
    - fix #1332084 - [RFE] Inclusion of lsns command in util-linux Package
    - fix #1335671 - extra quotes around UUID confuses findfs in RHEL (but not in Fedora)
    - fix #1344222 - logger port option in help is misleading
    - fix #1344482 - util-linux fails valid_pmbr() size checks if device is > 2.14TB, Device label type: dos
    instead of gpt
    - fix #587393 - [RFE] Make sure util-linux is ready for writable overlays

    [2.23.2-28]
    - fix #1291554 - lslogins crash when executed with buggy username

    [2.23.2-27]
    - fix #1301091 - [libblkid] Failed to get offset of the xfs_external_log signature

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2016-2605.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'libblkid-2.23.2-33.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-2.23.2-33.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-2.23.2-33.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-2.23.2-33.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-2.23.2-33.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-2.23.2-33.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-2.23.2-33.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-2.23.2-33.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-2.23.2-33.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-2.23.2-33.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-2.23.2-33.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-2.23.2-33.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-2.23.2-33.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-2.23.2-33.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-2.23.2-33.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-2.23.2-33.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libblkid / libblkid-devel / libmount / etc');
}
