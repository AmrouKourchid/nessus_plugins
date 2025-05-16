#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-0063.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156664);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2020-25704", "CVE-2020-36322", "CVE-2021-42739");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2022-0063)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-0063 advisory.

    [3.10.0-1160.53.1.OL7]
    - Update Oracle Linux certificates (Ilya Okomin)
    - Oracle Linux RHCK Module Signing Key was compiled into kernel
    (olkmod_signing_key.x509)(alexey.petrenko@oracle.com)
    - Update x509.genkey [Orabug: 24817676]
    - Conflict with shim-ia32 and shim-x64 <= 15-2.0.9
    - Update oracle(kernel-sig-key) value to match new certificate (Ilya Okomin)

    [3.10.0-1160.53.1]
    - fuse: fix live lock in fuse_iget() (Miklos Szeredi) [1952046]
    - fuse: fix bad inode (Miklos Szeredi) [1952046]
    - GFS2: Truncate address space mapping when deleting an inode (Bob Peterson) [1364234]
    - gfs2: Fix gfs2_testbit to use clone bitmaps (Bob Peterson) [1364234]
    - gfs2: clear buf_in_tr when ending a transaction in sweep_bh_for_rgrps (Bob Peterson) [1364234]
    - gfs2: Fix oversight in gfs2_ail1_flush (Bob Peterson) [1364234]
    - gfs2: Additional information when gfs2_ail1_flush withdraws (Bob Peterson) [1364234]
    - gfs2: leaf_dealloc needs to allocate one more revoke (Bob Peterson) [1364234]
    - gfs2: allow journal replay to hold sd_log_flush_lock (Bob Peterson) [1364234]
    - gfs2: don't allow releasepage to free bd still used for revokes (Bob Peterson) [1364234]
    - gfs2: flesh out delayed withdraw for gfs2_log_flush (Bob Peterson) [1364234]
    - gfs2: Do proper error checking for go_sync family of glops functions (Bob Peterson) [1364234]
    - gfs2: drain the ail2 list after io errors (Bob Peterson) [1364234]
    - gfs2: Withdraw in gfs2_ail1_flush if write_cache_pages fails (Bob Peterson) [1364234]
    - gfs2: Do log_flush in gfs2_ail_empty_gl even if ail list is empty (Bob Peterson) [1364234]
    - gfs2: Check for log write errors before telling dlm to unlock (Bob Peterson) [1364234]
    - gfs2: Prepare to withdraw as soon as an IO error occurs in log write (Bob Peterson) [1364234]
    - gfs2: Issue revokes more intelligently (Bob Peterson) [1364234]
    - gfs2: Add verbose option to check_journal_clean (Bob Peterson) [1364234]
    - gfs2: fix infinite loop when checking ail item count before go_inval (Bob Peterson) [1364234]
    - gfs2: Force withdraw to replay journals and wait for it to finish (Bob Peterson) [1364234]
    - gfs2: Allow some glocks to be used during withdraw (Bob Peterson) [1364234]
    - gfs2: move check_journal_clean to util.c for future use (Bob Peterson) [1364234]
    - gfs2: Ignore dlm recovery requests if gfs2 is withdrawn (Bob Peterson) [1364234]
    - gfs2: Only complain the first time an io error occurs in quota or log (Bob Peterson) [1364234]
    - gfs2: log error reform (Bob Peterson) [1364234]
    - gfs2: Rework how rgrp buffer_heads are managed (Bob Peterson) [1364234]
    - gfs2: clear ail1 list when gfs2 withdraws (Bob Peterson) [1364234]
    - gfs2: Introduce concept of a pending withdraw (Bob Peterson) [1364234]
    - gfs2: Return bool from gfs2_assert functions (Bob Peterson) [1364234]
    - gfs2: Turn gfs2_consist into void functions (Bob Peterson) [1364234]
    - gfs2: Remove usused cluster_wide arguments of gfs2_consist functions (Bob Peterson) [1364234]
    - gfs2: Report errors before withdraw (Bob Peterson) [1364234]
    - gfs2: Split gfs2_lm_withdraw into two functions (Bob Peterson) [1364234]
    - gfs2: Fix incorrect variable name (Bob Peterson) [1364234]
    - gfs2: Don't write log headers after file system withdraw (Bob Peterson) [1364234]
    - gfs2: clean up iopen glock mess in gfs2_create_inode (Bob Peterson) [1364234]
    - gfs2: Close timing window with GLF_INVALIDATE_IN_PROGRESS (Bob Peterson) [1364234]
    - gfs2: fix infinite loop in gfs2_ail1_flush on io error (Bob Peterson) [1364234]
    - gfs2: Introduce function gfs2_withdrawn (Bob Peterson) [1364234]
    - gfs2: replace more printk with calls to fs_info and friends (Bob Peterson) [1364234]
    - gfs2: dump fsid when dumping glock problems (Bob Peterson) [1364234]
    - gfs2: simplify gfs2_freeze by removing case (Bob Peterson) [1364234]
    - gfs2: Rename SDF_SHUTDOWN to SDF_WITHDRAWN (Bob Peterson) [1364234]
    - gfs2: Warn when a journal replay overwrites a rgrp with buffers (Bob Peterson) [1364234]
    - gfs2: log which portion of the journal is replayed (Bob Peterson) [1364234]
    - gfs2: slow the deluge of io error messages (Bob Peterson) [1364234]
    - gfs2: Don't withdraw under a spin lock (Bob Peterson) [1364234]
    - GFS2: Clear gl_object when deleting an inode in gfs2_delete_inode (Bob Peterson) [1364234]
    - gfs2: Use fs_* functions instead of pr_* function where we can (Bob Peterson) [1364234]
    more consistently (Bob Peterson) [1364234]

    [3.10.0-1160.52.1]
    - acpi-cpufreq: Honor _PSD table setting on new AMD CPUs (David Arcari) [2019588]
    - x86/cpu/amd: Call init_amd_zn() om Family 19h processors too (David Arcari) [2019218]
    - x86/cpu/AMD: Fix erratum 1076 (CPB bit) (David Arcari) [2019218]
    - i40e: Fix the conditional for i40e_vc_validate_vqs_bitmaps (Stefan Assmann) [1977246]
    - i40e: Fix virtchnl_queue_select bitmap validation (Stefan Assmann) [1977246]

    [3.10.0-1160.51.1]
    - mm, fs: Fix do_generic_file_read() error return (Carlos Maiolino) [2020857]
    - perf/core: Fix a memory leak in perf_event_parse_addr_filter() (Michael Petlan) [1901932]

    [3.10.0-1160.50.1]
    - tcp: grow window for OOO packets only for SACK flows (Guillaume Nault) [1990665]
    - scsi: mpt3sas: Fix unlock imbalance (Tomas Henzl) [2006536]
    - pci-hyperv: Fix setting CPU affinity on Azure (Vitaly Kuznetsov) [2019272]
    - media: firewire: firedtv-avc: fix a buffer overflow in avc_ca_pmt() (Lucas Zampieri) [1956471]
    {CVE-2021-42739}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-0063.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42739");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
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
  var fixed_uptrack_levels = ['3.10.0-1160.53.1.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-0063');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.10';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-1160.53.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-whitelists / etc');
}
