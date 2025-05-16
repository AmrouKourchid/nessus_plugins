##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9366.
##

include('compat.inc');

if (description)
{
  script_id(160983);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2022-27666");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel-container (ELSA-2022-9366)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has a package installed that is affected by a vulnerability as referenced in the
ELSA-2022-9366 advisory.

    - esp: Fix possible buffer overflow in ESP transformation (Steffen Klassert)  [Orabug: 33997301]
    {CVE-2022-27666}
    - netfilter: nf_tables: initialize registers in nft_do_chain() (Pablo Neira Ayuso)  [Orabug: 34012925]
    {CVE-2022-1016}
    - btrfs: unlock newly allocated extent buffer after error (Qu Wenruo)  [Orabug: 33997138]  {CVE-2021-4149}
    - sr9700: sanity check for packet length (Oliver Neukum)  [Orabug: 33962706]  {CVE-2022-26966}
    - lib/timerqueue: Rely on rbtree semantics for next timer (Davidlohr Bueso)  [Orabug: 33406086]
    {CVE-2021-20317}
    - NFSv4: Handle case where the lookup of a directory fails (Trond Myklebust)  [Orabug: 33958155]
    {CVE-2022-24448}
    - x86/speculation: Add knob for eibrs_retpoline_enabled (Patrick Colp)  [Orabug: 33937656]
    {CVE-2021-26401}
    - x86/speculation: Extend our code to properly support eibrs+lfence and eibrs+retpoline (Patrick Colp)
    [Orabug: 33937656]  {CVE-2021-26401}
    - x86/speculation: Update link to AMD speculation whitepaper (Kim Phillips)  [Orabug: 33937656]
    {CVE-2021-26401}
    - x86/speculation: Use generic retpoline by default on AMD (Kim Phillips)  [Orabug: 33937656]
    {CVE-2021-26401}
    - x86/speculation: Include unprivileged eBPF status in Spectre v2 mitigation reporting (Josh Poimboeuf)
    [Orabug: 33937656]  {CVE-2021-26401}
    - Documentation/hw-vuln: Update spectre doc (Peter Zijlstra)  [Orabug: 33937656]  {CVE-2021-26401}
    - x86/speculation: Add eIBRS + Retpoline options (Peter Zijlstra)  [Orabug: 33937656]  {CVE-2021-26401}
    - x86/speculation: Rename RETPOLINE_AMD to RETPOLINE_LFENCE (Peter Zijlstra (Intel))  [Orabug: 33937656]
    {CVE-2021-26401}
    - x86/speculation: Merge one test in spectre_v2_user_select_mitigation() (Borislav Petkov)  [Orabug:
    33937656]  {CVE-2021-26401}
    - x86/speculation: Update ALTERNATIVEs to (more closely) match upstream (Patrick Colp)  [Orabug: 33937656]
    {CVE-2021-26401}
    - x86/speculation: Fix bug in retpoline mode on AMD with 'spectre_v2=none' (Patrick Colp)  [Orabug:
    33937656]  {CVE-2021-26401}
    - ipv4: tcp: send zero IPID in SYNACK messages (Eric Dumazet)  [Orabug: 33917057]  {CVE-2020-36516}
    - ipv4: avoid using shared IP generator for connected sockets (Eric Dumazet)  [Orabug: 33917057]
    {CVE-2020-36516}
    - lib/iov_iter: initialize 'flags' in new pipe_buffer (Max Kellermann)  [Orabug: 33910800]
    {CVE-2022-0847}
    - udf: Restore i_lenAlloc when inode expansion fails (Jan Kara)  [Orabug: 33870267]  {CVE-2022-0617}
    - udf: Fix NULL ptr deref when converting from inline format (Jan Kara)  [Orabug: 33870267]
    {CVE-2022-0617}
    - drm/vmwgfx: Fix stale file descriptors on failed usercopy (Mathias Krause)  [Orabug: 33840433]
    {CVE-2022-22942}
    - drm/i915: Flush TLBs before releasing backing store (Tvrtko Ursulin)  [Orabug: 33835811]
    {CVE-2022-0330}
    - hugetlbfs: flush TLBs correctly after huge_pmd_unshare (Nadav Amit)  [Orabug: 33617219]  {CVE-2021-4002}
    - tipc: improve size validations for received domain records (Jon Maloy)  [Orabug: 33850803]
    {CVE-2022-0435}
    - cgroup-v1: Require capabilities to set release_agent (Eric W. Biederman)  [Orabug: 33825688]
    {CVE-2022-0492}
    - Linux 4.14.257 (Greg Kroah-Hartman)   {CVE-2021-38199}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9366.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27666");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.14.35-2047.513.2.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-9366');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-container-4.14.35-2047.513.2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-4.14.35'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek-container');
}
