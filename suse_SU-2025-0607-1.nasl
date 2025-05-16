#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0607-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216650);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2024-45774",
    "CVE-2024-45775",
    "CVE-2024-45776",
    "CVE-2024-45777",
    "CVE-2024-45778",
    "CVE-2024-45779",
    "CVE-2024-45780",
    "CVE-2024-45781",
    "CVE-2024-45782",
    "CVE-2024-45783",
    "CVE-2024-56737",
    "CVE-2025-0622",
    "CVE-2025-0624",
    "CVE-2025-0677",
    "CVE-2025-0678",
    "CVE-2025-0684",
    "CVE-2025-0685",
    "CVE-2025-0686",
    "CVE-2025-0689",
    "CVE-2025-0690",
    "CVE-2025-1118",
    "CVE-2025-1125"
  );
  script_xref(name:"IAVA", value:"2024-A-0207");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0607-1");

  script_name(english:"SUSE SLES15 Security Update : grub2 (SUSE-SU-2025:0607-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0607-1 advisory.

    - CVE-2024-45781: Fixed strcpy overflow in ufs. (bsc#1233617)
    - CVE-2024-56737: Fixed a heap-based buffer overflow in hfs. (bsc#1234958)
    - CVE-2024-45782: Fixed strcpy overflow in hfs. (bsc#1233615)
    - CVE-2024-45780: Fixed an overflow in tar/cpio. (bsc#1233614)
    - CVE-2024-45783: Fixed a refcount overflow in hfsplus. (bsc#1233616)
    - CVE-2024-45774: Fixed a heap overflow in JPEG parser. (bsc#1233609)
    - CVE-2024-45775: Fixed a missing NULL check in extcmd parser. (bsc#1233610)
    - CVE-2024-45776: Fixed an overflow in .MO file handling. (bsc#1233612)
    - CVE-2024-45777: Fixed an integer overflow in gettext. (bsc#1233613)
    - CVE-2024-45778: Fixed bfs filesystem by removing it from lockdown capable modules. (bsc#1233606)
    - CVE-2024-45779: Fixed a heap overflow in bfs. (bsc#1233608)
    - CVE-2025-0624: Fixed an out-of-bounds write during the network boot process. (bsc#1236316)
    - CVE-2025-0622: Fixed a use-after-free when handling hooks during module unload in command/gpg .
    (bsc#1236317)
    - CVE-2025-0690: Fixed an integer overflow that may lead to an out-of-bounds write through the read
    command.
      (bsc#1237012)
    - CVE-2025-1118: Fixed an issue where the dump command was not being blocked when grub was in lockdown
    mode.
      (bsc#1237013)
    - CVE-2025-0677: Fixed an integer overflow that may lead to an out-of-bounds write when handling symlinks
    in ufs.
      (bsc#1237002)
    - CVE-2025-0684: Fixed an integer overflow that may lead to an out-of-bounds write when handling symlinks
    in reiserfs.
      (bsc#1237008)
    - CVE-2025-0685: Fixed an integer overflow that may lead to an out-of-bounds write when handling symlinks
    in jfs.
      (bsc#1237009)
    - CVE-2025-0686: Fixed an integer overflow that may lead to an out-of-bounds write when handling symlinks
    in romfs.
      (bsc#1237010)
    - CVE-2025-0689: Fixed a heap-based buffer overflow in udf that may lead to arbitrary code execution.
    (bsc#1237011)
    - CVE-2025-1125: Fixed an integer overflow that may lead to an out-of-bounds write in hfs. (bsc#1237014)
    - CVE-2025-0678: Fixed an integer overflow that may lead to an out-of-bounds write in squash4.
    (bsc#1237006)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237014");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020379.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90891a06");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0624");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-1118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-1125");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0678");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-arm64-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-i386-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-powerpc-ieee1275");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-s390x-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-snapper-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-systemd-sleep-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-x86_64-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-x86_64-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'grub2-2.04-150300.22.52.3', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'grub2-arm64-efi-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'grub2-i386-pc-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'grub2-powerpc-ieee1275-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'grub2-snapper-plugin-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'grub2-systemd-sleep-plugin-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'grub2-x86_64-efi-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'grub2-x86_64-xen-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'grub2-2.04-150300.22.52.3', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'grub2-2.04-150300.22.52.3', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'grub2-arm64-efi-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'grub2-i386-pc-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'grub2-powerpc-ieee1275-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'grub2-snapper-plugin-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'grub2-systemd-sleep-plugin-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'grub2-x86_64-efi-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'grub2-x86_64-xen-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'grub2-2.04-150300.22.52.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'grub2-s390x-emu-2.04-150300.22.52.3', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2 / grub2-arm64-efi / grub2-i386-pc / grub2-powerpc-ieee1275 / etc');
}
