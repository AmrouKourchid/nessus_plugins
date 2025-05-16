#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9274.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159644);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2020-36516",
    "CVE-2021-22600",
    "CVE-2021-26341",
    "CVE-2021-26401",
    "CVE-2022-0617",
    "CVE-2022-1016",
    "CVE-2022-1158",
    "CVE-2022-22942",
    "CVE-2022-23960",
    "CVE-2022-24448",
    "CVE-2022-26966"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel-container (ELSA-2022-9274)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2022-9274 advisory.

    - KVM: x86/mmu: do compare-and-exchange of gPTE via the user address (Paolo
      Bonzini)  [Orabug: 34053807]  {CVE-2022-1158}
    - netfilter: nf_tables: initialize registers in nft_do_chain() (Pablo Neira Ayuso)  [Orabug: 34035701]
    {CVE-2022-1016}
    - sr9700: sanity check for packet length (Brian Maly)  [Orabug: 33962705]  {CVE-2022-26966}
    - net/packet: rx_owner_map depends on pg_vec (Willem de Bruijn)  [Orabug: 33835787]  {CVE-2021-22600}
    - NFSv4: Handle case where the lookup of a directory fails (Trond Myklebust)  [Orabug: 33958154]
    {CVE-2022-24448}
    - drm/vmwgfx: Fix stale file descriptors on failed usercopy (Mathias Krause)  [Orabug: 33840432]
    {CVE-2022-22942}
    - udf: Restore i_lenAlloc when inode expansion fails (Jan Kara)  [Orabug: 33870266]  {CVE-2022-0617}
    - udf: Fix NULL ptr deref when converting from inline format (Jan Kara)  [Orabug: 33870266]
    {CVE-2022-0617}
    - ipv4: tcp: send zero IPID in SYNACK messages (Eric Dumazet)  [Orabug: 33917056]  {CVE-2020-36516}
    - ipv4: avoid using shared IP generator for connected sockets (Eric Dumazet)  [Orabug: 33917056]
    {CVE-2020-36516}
    - arm64: Use the clearbhb instruction in mitigations (James Morse)  [Orabug: 33921736]  {CVE-2022-23960}
    - arm64: add ID_AA64ISAR2_EL1 sys register (Joey Gouly)  [Orabug: 33921736]  {CVE-2022-23960}
    - KVM: arm64: Allow SMCCC_ARCH_WORKAROUND_3 to be discovered and migrated (James Morse)  [Orabug:
    33921736]  {CVE-2022-23960}
    - arm64: Mitigate spectre style branch history side channels (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - KVM: arm64: Add templates for BHB mitigation sequences (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: Add Cortex-X2 CPU part definition (Anshuman Khandual)  [Orabug: 33921736]  {CVE-2022-23960}
    - arm64: Add Neoverse-N2, Cortex-A710 CPU part definition (Suzuki K Poulose)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: Add part number for Arm Cortex-A77 (Rob Herring)  [Orabug: 33921736]  {CVE-2022-23960}
    - arm64: proton-pack: Report Spectre-BHB vulnerabilities as part of Spectre-v2 (James Morse)  [Orabug:
    33921736]  {CVE-2022-23960}
    - arm64: Add percpu vectors for EL1 (James Morse)  [Orabug: 33921736]  {CVE-2022-23960}
    - arm64: entry: Add macro for reading symbol addresses from the trampoline (James Morse)  [Orabug:
    33921736]  {CVE-2022-23960}
    - arm64: entry: Add vectors that have the bhb mitigation sequences (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: entry: Add non-kpti __bp_harden_el1_vectors for mitigations (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: entry: Allow the trampoline text to occupy multiple pages (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: entry: Make the kpti trampoline's kpti sequence optional (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: entry: Move trampoline macros out of ifdef'd section (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: entry: Don't assume tramp_vectors is the start of the vectors (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: entry: Allow tramp_alias to access symbols after the 4K boundary (James Morse)  [Orabug:
    33921736]  {CVE-2022-23960}
    - arm64: entry: Move the trampoline data page before the text page (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: entry: Free up another register on kpti's tramp_exit path (James Morse)  [Orabug: 33921736]
    {CVE-2022-23960}
    - arm64: entry: Make the trampoline cleanup optional (James Morse)  [Orabug: 33921736]  {CVE-2022-23960}
    - arm64: entry.S: Add ventry overflow sanity checks (James Morse)  [Orabug: 33921736]  {CVE-2022-23960}
    - Revert 'BACKPORT: VARIANT 2: arm64: Add initial retpoline support' (Russell King)  [Orabug: 33921736]
    {CVE-2022-23960}
    - Revert 'BACKPORT: VARIANT 2: arm64: asm: Use *_nospec variants for blr and br.' (Russell King)  [Orabug:
    33921736]  {CVE-2022-23960}
    - Revert 'BACKPORT: VARIANT 2: arm64: Add MIDR_APM_POTENZA.' (Russell King)  [Orabug: 33921736]
    {CVE-2022-23960}
    - Revert 'BACKPORT: VARIANT 2: arm64: insn: Add offset getter/setter for adr.' (Russell King)  [Orabug:
    33921736]  {CVE-2022-23960}
    - Revert 'BACKPORT: VARIANT 2: arm64: alternatives: Add support for adr/adrp with offset in alt block.'
    (Russell King)  [Orabug: 33921736]  {CVE-2022-23960}
    - Revert 'BACKPORT: VARIANT 2: arm64: Use alternative framework for retpoline.' (Russell King)  [Orabug:
    33921736]  {CVE-2022-23960}
    - Revert 'Arm64: add retpoline to cpu_show_spectre_v2' (Russell King)  [Orabug: 33921736]
    {CVE-2022-23960}
    - Revert 'arm64: retpoline: Don't use retpoline in KVM's HYP part.' (Russell King)  [Orabug: 33921736]
    {CVE-2022-23960}
    - Revert 'uek-rpm: aarch64 config enable RETPOLINE' (Russell King)  [Orabug: 33921736]  {CVE-2022-23960}
    - Revert 'uek-rpm: aarch64 config enable RETPOLINE OL8' (Russell King)  [Orabug: 33921736]
    {CVE-2022-23960}
    - x86/speculation: Add knob for eibrs_retpoline_enabled (Patrick Colp)  [Orabug: 33941936]
    {CVE-2021-26401}
    - x86/speculation: Extend our code to properly support eibrs+lfence and eibrs+retpoline (Patrick Colp)
    [Orabug: 33941936]  {CVE-2021-26401}
    - x86/speculation: Update link to AMD speculation whitepaper (Kim Phillips)  [Orabug: 33941936]
    {CVE-2021-26401}
    - x86/speculation: Use generic retpoline by default on AMD (Kim Phillips)  [Orabug: 33941936]
    {CVE-2021-26401}
    - x86/speculation: Include unprivileged eBPF status in Spectre v2 mitigation reporting (Josh Poimboeuf)
    [Orabug: 33941936]  {CVE-2021-26401}
    - Documentation/hw-vuln: Update spectre doc (Peter Zijlstra)  [Orabug: 33941936]  {CVE-2021-26401}
    - x86/speculation: Add eIBRS + Retpoline options (Peter Zijlstra)  [Orabug: 33941936]  {CVE-2021-26401}
    - x86/speculation: Rename RETPOLINE_AMD to RETPOLINE_LFENCE (Peter Zijlstra (Intel))  [Orabug: 33941936]
    {CVE-2021-26401}
    - x86/speculation: Merge one test in spectre_v2_user_select_mitigation() (Borislav Petkov)  [Orabug:
    33941936]  {CVE-2021-26401}
    - x86/speculation: Update ALTERNATIVEs to (more closely) match upstream (Patrick Colp)  [Orabug: 33941936]
    {CVE-2021-26401}
    - x86/speculation: Fix bug in retpoline mode on AMD with  (Patrick Colp)  [Orabug: 33941936]
    {CVE-2021-26401}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9274.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container and / or kernel-uek-container-debug packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22600");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-22942");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7 / 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.306.1.3.el7', '5.4.17-2136.306.1.3.el8'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-9274');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.4';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-container-5.4.17-2136.306.1.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.306.1.3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.306.1.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.306.1.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek-container / kernel-uek-container-debug');
}
