#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3349-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(179970);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2018-3639",
    "CVE-2022-40982",
    "CVE-2023-0459",
    "CVE-2023-2985",
    "CVE-2023-3567",
    "CVE-2023-3609",
    "CVE-2023-3611",
    "CVE-2023-3776",
    "CVE-2023-20569",
    "CVE-2023-20593",
    "CVE-2023-35001"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3349-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2023:3349-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:3349-1 advisory.

  - Systems with microprocessors utilizing speculative execution and speculative execution of memory reads
    before the addresses of all prior memory writes are known may allow unauthorized disclosure of information
    to an attacker with local user access via a side-channel analysis, aka Speculative Store Bypass (SSB),
    Variant 4. (CVE-2018-3639)

  - Information exposure through microarchitectural state after transient execution in certain vector
    execution units for some Intel(R) Processors may allow an authenticated user to potentially enable
    information disclosure via local access. (CVE-2022-40982)

  - Copy_from_user on 64-bit versions of the Linux kernel does not implement the __uaccess_begin_nospec
    allowing a user to bypass the access_ok check and pass a kernel pointer to copy_from_user(). This would
    allow an attacker to leak information. We recommend upgrading beyond commit
    74e19ef0ff8061ef55957c3abd71614ef0f42f47 (CVE-2023-0459)

  - A side channel vulnerability on some of the AMD CPUs may allow an attacker to influence the return address
    prediction. This may result in speculative execution at an attacker-controlled?address, potentially
    leading to information disclosure. (CVE-2023-20569)

  - An issue in Zen 2 CPUs, under specific microarchitectural circumstances, may allow an attacker to
    potentially access sensitive information. (CVE-2023-20593)

  - A use after free flaw was found in hfsplus_put_super in fs/hfsplus/super.c in the Linux Kernel. This flaw
    could allow a local user to cause a denial of service problem. (CVE-2023-2985)

  - Linux Kernel nftables Out-Of-Bounds Read/Write Vulnerability; nft_byteorder poorly handled vm register
    contents when CAP_NET_ADMIN is in any user or network namespace (CVE-2023-35001)

  - A use-after-free flaw was found in vcs_read in drivers/tty/vt/vc_screen.c in vc_screen in the Linux
    Kernel. This flaw allows an attacker with local user access to cause a system crash or leak internal
    kernel information. (CVE-2023-3567)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to
    achieve local privilege escalation. If tcf_change_indev() fails, u32_set_parms() will immediately return
    an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can
    control the reference counter and set it to zero, they can cause the reference to be freed, leading to a
    use-after-free vulnerability. We recommend upgrading past commit 04c55383fa5689357bcdd2c8036725a55ed632bc.
    (CVE-2023-3609)

  - An out-of-bounds write vulnerability in the Linux kernel's net/sched: sch_qfq component can be exploited
    to achieve local privilege escalation. The qfq_change_agg() function in net/sched/sch_qfq.c allows an out-
    of-bounds write because lmax is updated according to packet sizes without bounds checks. We recommend
    upgrading past commit 3e337087c3b5805fe0b8a46ba622a962880b5d64. (CVE-2023-3611)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to
    achieve local privilege escalation. If tcf_change_indev() fails, fw_set_parms() will immediately return an
    error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can
    control the reference counter and set it to zero, they can cause the reference to be freed, leading to a
    use-after-free vulnerability. We recommend upgrading past commit 0323bce598eea038714f941ce2b22541c46d488f.
    (CVE-2023-3776)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1087082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1150305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213827");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-August/031064.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-3639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0459");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3776");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3639");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-3776");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-4.12.14-16.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-base-4.12.14-16.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-devel-4.12.14-16.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-devel-azure-4.12.14-16.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-source-azure-4.12.14-16.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-syms-azure-4.12.14-16.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-4.12.14-16.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-azure-base-4.12.14-16.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-azure-devel-4.12.14-16.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-azure-4.12.14-16.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-azure-4.12.14-16.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-azure-4.12.14-16.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-base / kernel-azure-devel / etc');
}
