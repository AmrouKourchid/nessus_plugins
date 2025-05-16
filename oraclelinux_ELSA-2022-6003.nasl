##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-6003.
##

include('compat.inc');

if (description)
{
  script_id(164032);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2022-0494", "CVE-2022-1055");

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2022-6003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-6003 advisory.

    [5.14.0-70.22.1.0.1_0.OL9]
    [lockdown: also lock down previous kgdb use (Daniel Thompson) [Orabug: 34290418] {CVE-2022-21499}

    [5.14.0-70.22.1_0.OL9]
    [Update Oracle Linux certificates (Kevin Lyons)
    [Disable signing for aarch64 (Ilya Okomin)
    [Oracle Linux RHCK Module Signing Key was added to the kernel trusted keys list (olkmod_signing_key.pem)
    [Orabug: 29539237]
    [Update x509.genkey [Orabug: 24817676]
    [Conflict with shim-ia32 and shim-x64 < 15.3-1.0.4
    [Remove nmap references from kernel (Mridula Shastry) [Orabug: 34313944]

    [5.14.0-70.22.1_0]
    [PCI: vmd: Revert 2565e5b69c44 ('PCI: vmd: Do not disable MSI-X remapping if interrupt remapping is
    enabled by IOMMU.') (Myron Stowe) [2109974 2084146]
    [PCI: vmd: Assign VMD IRQ domain before enumeration (Myron Stowe) [2109974 2084146]
    [rhel config: Set DMAR_UNITS_SUPPORTED (Jerry Snitselaar) [2105326 2094984]
    [iommu/vt-d: Make DMAR_UNITS_SUPPORTED a config setting (Jerry Snitselaar) [2105326 2094984]

    [5.14.0-70.21.1_0]
    [ibmvnic: fix race between xmit and reset (Gustavo Walbon) [2103085 2061556]
    [scsi: core: sysfs: Fix setting device state to SDEV_RUNNING (Chris Leech) [2098251 2095440]
    [scsi: core: sysfs: Fix hang when device state is set via sysfs (Chris Leech) [2098251 2095440]

    [5.14.0-70.20.1_0]
    [block-map: add __GFP_ZERO flag for alloc_page in function bio_copy_kern (Ming Lei) [2106024 2066297]
    {CVE-2022-0494}
    [ahci: Add a generic 'controller2' RAID id (Tomas Henzl) [2099740 2078880]
    [ahci: remove duplicated PCI device IDs (Tomas Henzl) [2099740 2042790]
    [gfs2: Stop using glock holder auto-demotion for now (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: buffered write prefaulting (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Align read and write chunks to the page cache (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Pull return value test out of should_fault_in_pages (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Clean up use of fault_in_iov_iter_{read,write}able (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Variable rename (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Fix filesystem block deallocation for short writes (Andreas Gruenbacher) [2097306 2082193]
    [iomap: iomap_write_end cleanup (Andreas Gruenbacher) [2097306 2082193]
    [iomap: iomap_write_failed fix (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Don't re-check for write past EOF unnecessarily (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: No short reads or writes upon glock contention (Andreas Gruenbacher) [2097306 2082193]
    [fs/iomap: Fix buffered write page prefaulting (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Make sure not to return short direct writes (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Remove dead code in gfs2_file_read_iter (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Fix gfs2_file_buffered_write endless loop workaround (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Minor retry logic cleanup (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Disable page faults during lockless buffered reads (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Fix should_fault_in_pages() logic (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Initialize gh_error in gfs2_glock_nq (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Make use of list_is_first (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Switch lock order of inode and iopen glock (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: cancel timed-out glock requests (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: Expect -EBUSY after canceling dlm locking requests (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: gfs2_setattr_size error path fix (Andreas Gruenbacher) [2097306 2082193]
    [gfs2: assign rgrp glock before compute_bitstructs (Bob Peterson) [2097306 2082193]

    [5.14.0-70.19.1_0]
    [KVM: x86/mmu: make apf token non-zero to fix bug (Vitaly Kuznetsov) [2100903 2074832]
    [powerpc/64: Move paca allocation later in boot (Desnes A. Nunes do Rosario) [2092248 2055566]
    [powerpc: Set crashkernel offset to mid of RMA region (Desnes A. Nunes do Rosario) [2092248 2055566]
    [powerpc/64s/hash: Make hash faults work in NMI context (Desnes A. Nunes do Rosario) [2092253 2062762]

    [5.14.0-70.18.1_0]
    [NFSv4: Fix free of uninitialized nfs4_label on referral lookup. (Benjamin Coddington) [2101858 2086367]
    [NFSv4 only print the label when its queried (Benjamin Coddington) [2101854 2057327]
    [crypto: fips - make proc files report fips module name and version (Simo Sorce) [2093384 2080499]
    [net: sched: fix use-after-free in tc_new_tfilter() (Ivan Vecera) [2071707 2090410] {CVE-2022-1055}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-6003.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0494");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1055");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2022-1055");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-70.22.1.0.1.el9_0'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-6003');
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
    {'reference':'bpftool-5.14.0-70.22.1.0.1.el9_0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-70.22.1.0.1.el9_0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-headers-5.14.0-70.22.1.0.1.el9_0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-tools-5.14.0-70.22.1.0.1.el9_0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-70.22.1.0.1.el9_0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-70.22.1.0.1.el9_0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'perf-5.14.0-70.22.1.0.1.el9_0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-70.22.1.0.1.el9_0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-devel-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'perf-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-70.22.1.0.1.el9_0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
