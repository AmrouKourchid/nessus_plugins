#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12444.
##

include('compat.inc');

if (description)
{
  script_id(200741);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id(
    "CVE-2024-2961",
    "CVE-2024-33599",
    "CVE-2024-33600",
    "CVE-2024-33601",
    "CVE-2024-33602"
  );
  script_xref(name:"IAVA", value:"2025-A-0062");

  script_name(english:"Oracle Linux 7 : glibc (ELSA-2024-12444)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12444 advisory.

    [2.17-326.0.9.3]
    - Forward-port Oracle patches to 2.17-326.3
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      Oracle history:
      June-22-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.17-326.0.9
      - OraBug 35517820 Reworked previous patch for OraBug 35318841 and removed
        free() of stack allocations.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      June-20-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.17-326.0.7
      - OraBug 35517820 Do not allocate heap memory in __nptl_tunables_init.
      - This issue was introduced and fixed in patch related to OraBug 35318841.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      April-21-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.17-326.0.5
      - OraBug 35318841 Glibc tunable to disable huge pages on pthread_create stacks
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      December-19-2022 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.17-326.0.3
      - OraBug 34909902 vDSO timer functions support on i686
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      May-18-2022 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.17-326.0.1
      - Forward-port Oracle patches to 2.17-326.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      April-26-2022 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.17-325.0.3
      - OraBug 33968985 Security Patches
        This release fixes CVE-2022-23219, CVE-2022-23218, and CVE-2021-3999
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      October-12-2021 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.17-325.0.1
      - Merge el7 u9 errata4 patch with Oracle patches
        Review-exception: Simple merge
      - Merge el7 u9 errata patches with Oracle patches
        Review-exception: Simple merge
      - Adding three arm specific patches to allow glibc x86 tree to be used for
      - ILOM and other arm builds
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - Merge el7 u8 patches with Oracle patches
        Review-exception: Simple merge
      - Adding Mike Fabian's C.utf-8 patch (C.utf-8 is a unicode-aware version
        of the C locale)
        Orabug 29784239.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - Remove glibc-ora28641867.patch as duplicate of glibc-rh1705899-4.patch
      - Make _IO_funlockfile match __funlockfile and _IO_flockfile match __flockfile
        Both should test
          if ((stream->_flags & _IO_USER_LOCK) == 0)
            _IO_lock_lock (*stream->_lock);
        OraBug 28481550.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - Modify glibc-ora28849085.patch so it works with RHCK kernels.
        Orabug 28849085.
      - Reviewed-by: Egeyar Bagcioglu <egeyar.bagcioglu@oracle.com>
      - Use NLM_F_SKIP_STATS in uek2 and RTEXT_FILTER_SKIP_STATS in uek4 in getifaddrs.
      - Orabug 28849085
      - Reviewed-by: Patrick McGehearty <patrick.mcgehearty@oracle.com>
      - Mention CVE numbers in the .spec file for CVE-2015-8983 and CVE-2015-8984.
      - Orabug 25558067.
      - Reviewed-by: Egeyar Bagcioglu <egeyar.bagcioglu@oracle.com>
      - Regenerate plural.c
      - OraBug 28806294.
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - intl: Port to Bison 3.0
      - Backport of upstream gettext commit 19f23e290a5e4a82b9edf9f5a4f8ab6192871be9
      - OraBug 28806294.
      - Reviewed-by: Patrick McGehearty <patrick.mcgehearty@oracle.com>
      - Fix dbl-64/wordsize-64 remquo (bug 17569).
      - Backport of upstream d9afe48d55a412e76b0dcb28335fd4b390fe07ae
      - OraBug 19570749.
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - libio: Disable vtable validation in case of interposition.
      - Backport of upstream c402355dfa7807b8e0adb27c009135a7e2b9f1b0.
      - OraBug 28641867.
      - Reviewed-by: Egeyar Bagcioglu <egeyar.bagcioglu@oracle.com>
      - Include-linux-falloc.h-in-bits-fcntl-linux.h
      - Defines FALLOC_FL_PUNSH_HOLE, FALLOC_FL_KEEP_SIZE,
        FALLOC_FL_COLLAPSE_RANGE, and FALLOC_FL_ZERO_RANGE
      - OraBug 28483336
      - Add MAP_SHARED_VALIDATE and MAP_SYNC flags to
      - sysdeps/unix/sysv/linux/x86/bits/mman.h
      - OraBug 28389572
      - Update bits/siginfo.h with Linux hwpoison SIGBUS changes.
      - Adds new SIGBUS error codes for hardware poison signals, syncing with
        the current kernel headers (v3.9).
      - It also adds si_trapno field for alpha.
      - New values: BUS_MCEERR_AR, BUS_MCEERR_AO
      - OraBug 28124569

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12444.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2961");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-33599");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::userspace_ksplice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'glibc-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-common-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-devel-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-headers-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-static-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-utils-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'nscd-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-common-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-devel-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-headers-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-static-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-utils-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'nscd-2.17-326.0.9.ksplice1.el7_9.3', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc / glibc-common / glibc-devel / etc');
}
