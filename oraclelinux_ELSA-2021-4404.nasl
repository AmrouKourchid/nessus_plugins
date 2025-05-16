#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-4404.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155420);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2021-20269");

  script_name(english:"Oracle Linux 8 : kexec-tools (ELSA-2021-4404)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has a package installed that is affected by a vulnerability as referenced in the
ELSA-2021-4404 advisory.

    [2.0.20-57.0.3]
    - Merge 8.4 extra patches for SB boot environment [Orabug: 33512440]

    [2.0.20-57.0.2]
    - Merge SRPM/ol8-u4 orabug patches into SRPM/ol8-u5 [Orabug: 33471981]

    [2.0.20-57.0.1]
    - makedumpfile: Add support for newer kernels up to v5.12 [Orabug: 33250117]

    [2.0.20-57]
    - kdumpctl: enable secure boot on ppc64le LPARs

    [2.0.20-56]
    - kdumpctl: fix a typo

    [2.0.20-55]
    - kdump/ppc64: migration action registration clean up

    [2.0.20-54]
    - kdump/ppc64: rebuild initramfs image after migration
    - Check the existence of /sys/bus/ccwgroup/devices/*/online beforehand
    - kdump.sysconfig.s390: Remove 'prot_virt' from kdump kernel cmdline

    [2.0.20-53]
    - check for invalid physical address of /proc/kcore when making ELF dumpfile
    - check for invalid physical address of /proc/kcore when finding max_paddr
    - fix format issue in find_online_znet_device
    - check the existence of /sys/bus/ccwgroup/devices before trying to find online network device
    - kdump-lib.sh: fix a warning in prepare_kdump_bootinfo()

    [2.0.20-52]
    - Write to /var/lib/kdump if  not writable
    - Iterate /sys/bus/ccwgroup/devices to tell if we should set up rd.znet
    - mkdumprd: display the absolute path of dump location in the check_user_configured_target()

    [2.0.20-51]
    - Stop reloading kdump service on CPU hotplug event for FADump
    - fadump: improve fadump-howto.txt about remote dump target setup

    [2.0.20-50]
    - rd.route should use the name from kdump_setup_ifname
    - get kdump ifname once in kdump_install_netdev

    [2.0.20-49]
    - kdump-lib.sh: fix the case if no enough total RAM for kdump  in get_recommend_size()

    [2.0.20-48]
    - kdumpctl: Add kdumpctl estimate
    - mkdumprd: make use of the new get_luks_crypt_dev helper
    - kdump-lib.sh: introduce a helper to get all crypt dev used by kdump
    - kdump-lib.sh: introduce a helper to get underlying crypt device
    - RHEL-only: keep total memory size coherent to RHEL-only kernel patch
    - Show write byte size in report messages
    - Add shorthand --show-stats option to show report stats
    - Add --dry-run option to prevent writing the dumpfile
    - kdump-lib.sh: introduce functions to return recommened mem size

    [2.0.20-47]
    - Implement IP netmask calculation to replace 'ipcalc -m'
    - kdumpctl: fix check_config error when kdump.conf is empty
    - Fix incorrect vmcore permissions when dumped through ssh
    - Fix incorrect permissions on kdump dmesg file

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-4404.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kexec-tools package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20269");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kexec-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'kexec-tools-2.0.20-57.0.3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kexec-tools-2.0.20-57.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kexec-tools');
}
