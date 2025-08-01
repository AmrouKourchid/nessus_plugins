#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4732.
##

include('compat.inc');

if (description)
{
  script_id(180714);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-11091"
  );
  script_xref(name:"IAVA", value:"2019-A-0166");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2019-4732)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-4732 advisory.

    - x86/speculation/mds: Conditionally clear CPU buffers on idle entry (Thomas Gleixner) [orabug 29821515]
    {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Call VERW on NMI path when returning to user (Patrick Colp) [orabug 29821515]
    {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Fix verw usage to use memory operand (Patrick Colp) [orabug 29821515]
    {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Make cpu_matches() __cpuinit (Patrick Colp) [orabug 29821515] {CVE-2018-12126}
    {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Add mitigation mode VMWERV (Thomas Gleixner) [orabug 29821515] {CVE-2018-12126}
    {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Add sysfs reporting for MDS (Thomas Gleixner) [orabug 29821515] {CVE-2018-12126}
    {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Add mitigation control for MDS (Thomas Gleixner) [orabug 29821515] {CVE-2018-12126}
    {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Improve coverage for MDS vulnerability (Boris Ostrovsky) [orabug 29821515]
    {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Clear CPU buffers on exit to user (Thomas Gleixner) [orabug 29821515]
    {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Add mds_clear_cpu_buffers() (Thomas Gleixner) [orabug 29821515] {CVE-2018-12126}
    {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Add BUG_MSBDS_ONLY (Thomas Gleixner) [orabug 29821515] {CVE-2018-12126}
    {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Add basic bug infrastructure for MDS (Andi Kleen) [orabug 29821515]
    {CVE-2018-12126} {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - x86/speculation/mds: Consolidate CPU whitelists (Thomas Gleixner) [orabug 29821515] {CVE-2018-12126}
    {CVE-2018-12130} {CVE-2018-12127} {CVE-2019-11091}
    - [x86] mm/dump_pagetables: Add a check_l1tf debugfs file (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] l1tf: protect _PAGE_FILE PTEs against speculation (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Extend 64bit swap file size limit (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] bugs: Move the l1tf function and define pr_fmt properly (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Limit swap file size to MAX_PA/2 (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Add sysfs reporting for l1tf (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Protect PROT_NONE PTEs against speculation (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Protect swap entries against L1TF (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Change order of offset/type in swap entry (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] speculation/l1tf: Increase 32bit PAE __PHYSICAL_PAGE_SHIFT (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] cpu: Fix incorrect vulnerabilities files function prototypes (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] bugs: Export the internal __cpu_bugs variable (Chris von Recklinghausen) [1593378] {CVE-2018-3620}
    - [x86] spec_ctrl: sync with upstream cpu_set_bug_bits() (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] intel-family.h: Add GEMINI_LAKE SOC (Chris von Recklinghausen) [1593378] {CVE-2018-3620}
    - [x86] mm: Fix swap entry comment and macro (Chris von Recklinghausen) [1593378] {CVE-2018-3620}
    - [x86] mm: Move swap offset/type up in PTE to work around erratum (Chris von Recklinghausen) [1593378]
    {CVE-2018-3620}
    - [x86] ia32entry: make target ia32_ret_from_sys_call the common exit point to long-mode (Rafael Aquini)
    [1570474] {CVE-2009-2910}
    - [x86] spec_ctrl: only perform RSB stuffing on SMEP capable CPUs (Rafael Aquini) [1570474]
    {CVE-2009-2910}
    - [net] tcp: fix 0 divide in __tcp_select_window (Davide Caratti) [1488343] {CVE-2017-14106}
    - [net] tcp: initialize rcv_mss to TCP_MIN_MSS instead of 0 (Davide Caratti) [1488343] {CVE-2017-14106}
    - [x86] Fix up /proc/cpuinfo entries (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - [kernel] spec_ctrl: work around broken microcode (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] Only expose PR_{GET, SET}_SPECULATION_CTRL if CONFIG_SPEC_CTRL is defined (Chris von
    Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] misc changes to fix i386 builds (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] amd: Disable AMD SSBD mitigation in a VM (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] spec_ctrl: add support for SSBD to RHEL IBRS entry/exit macros (Chris von Recklinghausen)
    [1566896] {CVE-2018-3639}
    - [x86] bugs: Rename _RDS to _SSBD (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] speculation: Add prctl for Speculative Store Bypass mitigation (Chris von Recklinghausen)
    [1566896] {CVE-2018-3639}
    - [x86] process: Allow runtime control of Speculative Store Bypass (Chris von Recklinghausen) [1566896]
    {CVE-2018-3639}
    - [x86] 64: add skeletonized version of __switch_to_xtra (Chris von Recklinghausen) [1566896]
    {CVE-2018-3639}
    - [kernel] prctl: Add speculation control prctls (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] bugs/AMD: Add support to disable RDS on Fam[15, 16, 17]h if requested (Chris von Recklinghausen)
    [1566896] {CVE-2018-3639}
    - [x86] spec_ctrl: Sync up RDS setting with IBRS code (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] bugs: Provide boot parameters for the spec_store_bypass_disable mitigation (Chris von
    Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] bugs: Expose the /sys/../spec_store_bypass and X86_BUG_SPEC_STORE_BYPASS (Chris von
    Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] include: add latest intel-family.h from RHEL6 (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - [x86] bugs: Read SPEC_CTRL MSR during boot and re-use reserved bits (Chris von Recklinghausen) [1566896]
    {CVE-2018-3639}
    - [x86] spec_ctrl: Use separate PCP variables for IBRS entry and exit (Chris von Recklinghausen) [1566896]
    {CVE-2018-3639}
    - [x86] cpuid: Fix up  IBRS/IBPB/STIBP feature bits on Intel (Chris von Recklinghausen) [1566896]
    {CVE-2018-3639}
    - [x86] cpufeatures: Clean up Spectre v2 related CPUID flags (Chris von Recklinghausen) [1566896]
    {CVE-2018-3639}
    - [x86] cpufeatures: Add AMD feature bits for Speculation Control (Chris von Recklinghausen) [1566896]
    {CVE-2018-3639}
    - [x86] cpufeatures: Add Intel feature bits for Speculation (Chris von Recklinghausen) [1566896]
    {CVE-2018-3639}
    - [x86] cpu: Add driver auto probing for x86 features (Chris von Recklinghausen) [1566896] {CVE-2018-3639}
    - x86_64/entry: Don't use IST entry for #BP stack [orabug 28452062] {CVE-2018-8897}
    - Backport CVE-2017-5715 to RHCK/OL5 [orabug 27787723]
    - Backport CVEs to RHCK/OL5 [orabug 27547712] {CVE-2017-5753} {CVE-2017-5754}
    - [fs] fix bug in loading of PIE binaries (Michael Davidson) [orabug 26916951] {CVE-2017-1000253}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-4732.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11091");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-419.0.0.0.14.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-419.0.0.0.14.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-419.0.0.0.14.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-419.0.0.0.14.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-419.0.0.0.14.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-419.0.0.0.14.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-419.0.0.0.14.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-419.0.0.0.14.el5xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.18-419.0.0.0.14.el5'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2019-4732');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-PAE-2.6.18-419.0.0.0.14.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-419.0.0.0.14.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-419.0.0.0.14.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5-1.4.11-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5PAE-1.4.11-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5debug-1.4.11-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5xen-1.4.11-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5-2.0.5-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5PAE-2.0.5-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5debug-2.0.5-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5xen-2.0.5-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-PAE-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5-1.4.11-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5PAE-1.4.11-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5debug-1.4.11-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5xen-1.4.11-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5-2.0.5-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5PAE-2.0.5-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5debug-2.0.5-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5xen-2.0.5-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-419.0.0.0.14.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-419.0.0.0.14.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-419.0.0.0.14.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-419.0.0.0.14.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-419.0.0.0.14.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5-1.4.11-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5debug-1.4.11-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-419.0.0.0.14.el5xen-1.4.11-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5-2.0.5-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5debug-2.0.5-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-419.0.0.0.14.el5xen-2.0.5-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-PAE / kernel-PAE-devel / etc');
}
