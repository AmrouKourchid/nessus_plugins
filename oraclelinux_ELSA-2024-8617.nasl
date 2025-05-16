#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-8617.
##

include('compat.inc');

if (description)
{
  script_id(210013);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/03");

  script_cve_id(
    "CVE-2021-47383",
    "CVE-2024-2201",
    "CVE-2024-26640",
    "CVE-2024-26826",
    "CVE-2024-26923",
    "CVE-2024-26935",
    "CVE-2024-26961",
    "CVE-2024-36244",
    "CVE-2024-39472",
    "CVE-2024-39504",
    "CVE-2024-40904",
    "CVE-2024-40931",
    "CVE-2024-40960",
    "CVE-2024-40972",
    "CVE-2024-40977",
    "CVE-2024-40995",
    "CVE-2024-40998",
    "CVE-2024-41005",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-43854",
    "CVE-2024-45018"
  );
  script_xref(name:"IAVA", value:"2024-A-0228-S");

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2024-8617)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-8617 advisory.

    - redhat/configs: Add CONFIG_MITIGATION_SPECTRE_BHI (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bugs: Fix BHI retpoline check (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bugs: Replace CONFIG_SPECTRE_BHI_{ON,OFF} with CONFIG_MITIGATION_SPECTRE_BHI (Waiman Long)
    [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bugs: Remove CONFIG_BHI_MITIGATION_AUTO and spectre_bhi=auto (Waiman Long) [RHEL-45492 RHEL-28203]
    {CVE-2024-2201}
    - x86/bugs: Clarify that syscall hardening isn't a BHI mitigation (Waiman Long) [RHEL-45492 RHEL-28203]
    {CVE-2024-2201}
    - x86/bugs: Fix BHI handling of RRSBA (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bugs: Rename various 'ia32_cap' variables to 'x86_arch_cap_msr' (Waiman Long) [RHEL-45492
    RHEL-28203] {CVE-2024-2201}
    - x86/bugs: Cache the value of MSR_IA32_ARCH_CAPABILITIES (Waiman Long) [RHEL-45492 RHEL-28203]
    {CVE-2024-2201}
    - x86/bugs: Fix BHI documentation (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bugs: Fix return type of spectre_bhi_state() (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bugs: Make CONFIG_SPECTRE_BHI_ON the default (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - KVM: x86: Add BHI_NO (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bhi: Mitigate KVM by default (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bhi: Add BHI mitigation knob (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bhi: Enumerate Branch History Injection (BHI) bug (Waiman Long) [RHEL-45492 RHEL-28203]
    {CVE-2024-2201}
    - x86/bhi: Define SPEC_CTRL_BHI_DIS_S (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - x86/bhi: Add support for clearing branch history at syscall entry (Waiman Long) [RHEL-45492 RHEL-28203]
    {CVE-2024-2201}
    - x86/bugs: Change commas to semicolons in 'spectre_v2' sysfs file (Waiman Long) [RHEL-45492 RHEL-28203]
    {CVE-2024-2201}
    - perf/x86/amd/lbr: Use freeze based on availability (Waiman Long) [RHEL-45492 RHEL-28203] {CVE-2024-2201}
    - Documentation/kernel-parameters: Add spec_rstack_overflow to mitigations=off (Waiman Long) [RHEL-45492
    RHEL-28203] {CVE-2024-2201}
    - scsi: core: Fix unremoved procfs host directory regression (Ewan D. Milne) [RHEL-39539 RHEL-39601
    RHEL-33543 RHEL-35000] {CVE-2024-26935}
    - tty: Fix out-of-bound vmalloc access in imageblit (Andrew Halaney) [RHEL-42095 RHEL-24205]
    {CVE-2021-47383}
    - block: initialize integrity buffer to zero before writing it to media (Ming Lei) [RHEL-54769 RHEL-54768]
    {CVE-2024-43854}
    - netfilter: nft_inner: validate mandatory meta and payload (Phil Sutter) [RHEL-47488 RHEL-47486]
    {CVE-2024-39504}
    - netfilter: flowtable: initialise extack before use (CKI Backport Bot) [RHEL-58546 RHEL-58544]
    {CVE-2024-45018}
    - ext4: do not create EA inode under buffer lock (Carlos Maiolino) [RHEL-48285 RHEL-48282]
    {CVE-2024-40972}
    - ext4: fold quota accounting into ext4_xattr_inode_lookup_create() (Carlos Maiolino) [RHEL-48285
    RHEL-48282] {CVE-2024-40972}
    - ext4: fix uninitialized ratelimit_state->lock access in __ext4_fill_super() (Carlos Maiolino)
    [RHEL-48519 RHEL-48517] {CVE-2024-40998}
    - ext4: turn quotas off if mount failed after enabling quotas (Carlos Maiolino) [RHEL-48519 RHEL-48517]
    {CVE-2024-40998}
    - mptcp: fix data re-injection from stale subflow (Davide Caratti) [RHEL-59920 RHEL-32669]
    {CVE-2024-26826}
    - xfs: add bounds checking to xlog_recover_process_data (CKI Backport Bot) [RHEL-50864 RHEL-50862]
    {CVE-2024-41014}
    - af_unix: Fix garbage collector racing against connect() (Davide Caratti) [RHEL-42771 RHEL-33410]
    {CVE-2024-26923}
    - xfs: don't walk off the end of a directory data block (CKI Backport Bot) [RHEL-50887 RHEL-50885]
    {CVE-2024-41013}
    - ipv6: prevent possible NULL dereference in rt6_probe() (Hangbin Liu) [RHEL-48161 RHEL-45826]
    {CVE-2024-40960}
    - mac802154: fix llsec key resources release in mac802154_llsec_key_del (Steve Best) [RHEL-42795
    RHEL-34969] {CVE-2024-26961}
    - mptcp: ensure snd_una is properly initialized on connect (Florian Westphal) [RHEL-47945 RHEL-47943]
    {CVE-2024-40931}
    - USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages (CKI Backport Bot) [RHEL-47560
    RHEL-47558] {CVE-2024-40904}
    - xfs: fix log recovery buffer allocation for the legacy h_size fixup (Bill O'Donnell) [RHEL-46481
    RHEL-46479] {CVE-2024-39472}
    - tcp: add sanity checks to rx zerocopy (Paolo Abeni) [RHEL-58403 RHEL-29496] {CVE-2024-26640}
    - netpoll: Fix race condition in netpoll_owner_active (CKI Backport Bot) [RHEL-49373 RHEL-49371]
    {CVE-2024-41005}
    - wifi: mt76: mt7921s: fix potential hung tasks during chip recovery (CKI Backport Bot) [RHEL-48321
    RHEL-48319] {CVE-2024-40977}
    - net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc() (Davide Caratti) [RHEL-48483
    RHEL-44375] {CVE-2024-40995}
    - net/sched: taprio: extend minimum interval restriction to entire cycle too (Davide Caratti) [RHEL-44377
    RHEL-44375] {CVE-2024-36244}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-8617.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26961");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:4:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-427.42.1.el9_4'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-8617');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-7.3.0-427.42.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-427.42.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-headers-5.14.0-427.42.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-tools-5.14.0-427.42.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-427.42.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-427.42.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'perf-5.14.0-427.42.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-427.42.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.3.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-debug-uki-virt-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-uki-virt-5.14.0'},
    {'reference':'kernel-devel-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'kernel-uki-virt-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uki-virt-5.14.0'},
    {'reference':'libperf-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-427.42.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
