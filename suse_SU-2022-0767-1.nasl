#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0767-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158752);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id(
    "CVE-2021-44879",
    "CVE-2021-45095",
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0487",
    "CVE-2022-0492",
    "CVE-2022-0617",
    "CVE-2022-0644",
    "CVE-2022-0847",
    "CVE-2022-24448",
    "CVE-2022-24959"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0767-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2022:0767-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2022:0767-1 advisory.

  - In gc_data_segment in fs/f2fs/gc.c in the Linux kernel before 5.16.3, special files are not considered,
    leading to a move_data_page NULL pointer dereference. (CVE-2021-44879)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local access. (CVE-2022-0001)

  - Non-transparent sharing of branch predictor within a context in some Intel(R) Processors may allow an
    authorized user to potentially enable information disclosure via local access. (CVE-2022-0002)

  - A use-after-free vulnerability was found in rtsx_usb_ms_drv_remove in drivers/memstick/host/rtsx_usb_ms.c
    in memstick in the Linux kernel. In this flaw, a local attacker with a user privilege may impact system
    Confidentiality. This flaw affects kernel versions prior to 5.14 rc1. (CVE-2022-0487)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A flaw null pointer dereference in the Linux kernel UDF file system functionality was found in the way
    user triggers udf_file_write_iter function for the malicious UDF image. A local user could use this flaw
    to crash the system. Actual from Linux kernel 4.2-rc1 till 5.17-rc2. (CVE-2022-0617)

  - A flaw was found in the way the flags member of the new pipe buffer structure was lacking proper
    initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus
    contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache
    backed by read only files and as such escalate their privileges on the system. (CVE-2022-0847)

  - An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5. If an application sets the
    O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a
    regular file is found, ENOTDIR should occur, but the server instead returns uninitialized data in the file
    descriptor. (CVE-2022-24448)

  - An issue was discovered in the Linux kernel before 5.16.5. There is a memory leak in yam_siocdevprivate in
    drivers/net/hamradio/yam.c. (CVE-2022-24959)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1046306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1050244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1089644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1094978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1101674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1101816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1103991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1111981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1119113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1136460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1136461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24448");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24959");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010399.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55fabd96");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Dirty Pipe Local Privilege Escalation via CVE-2022-0847');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED12|SLED_SAP12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-extra-4.12.14-122.113.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.113.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.113.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12.5', 'sle-ha-release-12.5', 'sles-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.113.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12.5', 'sle-ha-release-12.5', 'sles-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.113.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12.5', 'sle-ha-release-12.5', 'sles-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.113.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12.5', 'sle-ha-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.113.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sled-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.113.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sled-release-12.5', 'sles-release-12.5']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
