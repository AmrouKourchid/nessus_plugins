#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-2861.
##

include('compat.inc');

if (description)
{
  script_id(233579);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2025-26594",
    "CVE-2025-26595",
    "CVE-2025-26596",
    "CVE-2025-26597",
    "CVE-2025-26598",
    "CVE-2025-26599",
    "CVE-2025-26600",
    "CVE-2025-26601"
  );

  script_name(english:"Oracle Linux 7 : tigervnc (ELSA-2025-2861)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2025-2861 advisory.

    - Fix CVE-2025-26594 xorg-x11-server Use-after-free of the root cursor [Orabug: 37712725]
    - Fix CVE-2025-26595 xorg-x11-server Buffer overflow in XkbVModMaskText()
    - Fix CVE-2025-26596 xorg-x11-server Heap overflow in XkbWriteKeySyms()
    - Fix CVE-2025-26597 xorg-x11-server Buffer overflow in XkbChangeTypesOfKey()
    - Fix CVE-2025-26598 xorg-x11-server Out-of-bounds write in CreatePointerBarrierClient()
    - Fix CVE-2025-26599 xorg-x11-server Use of uninitialized pointer in compRedirectWindow()
    - Fix CVE-2025-26600 xorg-x11-server Use-after-free in PlayReleasedEvents()
    - Fix CVE-2025-26601 xorg-x11-server Use-after-free in SyncInitTrigger()
    - xorg-x11-server: xkb: Fix buffer overflow in _XkbSetCompatMap() [CVE-2024-9632][Orabug: 37295822]
    - Dropped xorg-CVE-2023-5367.patch, xorg-CVE-2023-6816.patch, xorg-CVE-2023-6377.patch, xorg-
    CVE-2023-6478.patch,
      xorg-CVE-2024-0229-1.patch, xorg-CVE-2024-0229-2.patch, xorg-CVE-2024-0229-3.patch, xorg-
    CVE-2024-21885.patch,
      xorg-CVE-2024-21886-1.patch, xorg-CVE-2024-21886-2.patch, xorg-dix-fix-use-after-free-in-input-device-
    shutdown.patch,
      xorg-CVE-2024-31080.patch, xorg-CVE-2024-31081.patch, xorg-CVE-2024-31082.patch, xorg-
    CVE-2024-31083.patch,
      xorg-CVE-2024-31083-followup.patch
    - Fix crash caused by fix for CVE-2024-31083
      Resolves: RHEL-30976
    - Fix CVE-2024-31080 tigervnc: xorg-x11-server: Heap buffer overread/data leakage in
    ProcXIGetSelectedEvents
      Resolves: RHEL-31006
    - Fix CVE-2024-31083 tigervnc: xorg-x11-server: User-after-free in ProcRenderAddGlyphs
      Resolves: RHEL-30976
    - Fix CVE-2024-31081 tigervnc: xorg-x11-server: Heap buffer overread/data leakage in
    ProcXIPassiveGrabDevice
      Resolves: RHEL-30993
    - Fix use after free related to CVE-2024-21886
      Resolves: RHEL-20436
    - Fix CVE-2024-21886 tigervnc: xorg-x11-server: heap buffer overflow in DisableDevice
      Resolves: RHEL-20436
    - Fix CVE-2024-21885 tigervnc: xorg-x11-server: heap buffer overflow in XISendDeviceHierarchyEvent
      Resolves: RHEL-20427
    - Fix CVE-2024-0229 tigervnc: xorg-x11-server: reattaching to different master device may lead to out-of-
    bounds memory access
      Resolves: RHEL-20587
    - Fix CVE-2023-6816 tigervnc: xorg-x11-server: Heap buffer overflow in DeviceFocusEvent and
    ProcXIQueryPointer
      Resolves: RHEL-21212
    - Updated fix for CVE-2023-6377 tigervnc: xorg-x11-server: out-of-bounds memory reads/writes in XKB button
    actions
      Resolves: RHEL-18415
    - Fix CVE-2023-6377 tigervnc: xorg-x11-server: out-of-bounds memory reads/writes in XKB button actions
      Resolves: RHEL-18415
    - CVE-2023-6478 tigervnc: xorg-x11-server: out-of-bounds memory read in RRChangeOutputProperty and
    RRChangeProviderProperty
      Resolves: RHEL-18427
    - Fix CVE-2023-5380 tigervnc: xorg-x11-server: Use-after-free bug in DestroyWindow
      Resolves: RHEL-15235
    - Fix CVE-2023-5367 tigervnc: xorg-x11-server: Out-of-bounds write in
    XIChangeDeviceProperty/RRChangeOutputProperty
      Resolves: RHEL-15223
    - CVE fix for: CVE-2023-1393
      Resolves: bz#2180291
    - CVE fix for: CVE-2023-0494
      Resolves: bz#2166532
    - Rebuild for xorg-x11-server CVEs
      Resolves: CVE-2022-4283 (bz#2154267)
      Resolves: CVE-2022-46340 (bz#2154261)
      Resolves: CVE-2022-46341 (bz#2154264)
      Resolves: CVE-2022-46342 (bz#2154262)
      Resolves: CVE-2022-46343 (bz#2154265)
      Resolves: CVE-2022-46344 (bz#2154266)
    - Delete underlying ssecurity in SSecurityVeNCrypt [CCVE-2017-7392]
      Resolves: bz#1439127
      Prevent double free by crafted fences [CVE-2017-7393]
      Resolves: bz#1439134
    - Be more restrictive with shared memory mode bits
      Resolves: bz#1152552
      Limit max username/password size in SSecurityPlain [CVE-2017-7394]
      Resolves: bz#1438737
      Fix crash from integer overflow in SMsgReader::readClientCutText [CVE-2017-7395]
      Resolves: bz#1438742
    - Resolves: bz#1248422
      CVE-2014-8240 CVE-2014-8241 tigervnc: various flaws
    - Fixed heap-based buffer overflow (CVE-2014-0011, bug #1050928).
    - patches merged
      - tigervnc11-glx.patch
      - tigervnc11-CVE-2011-1775.patch
      - 0001-Use-memmove-instead-of-memcpy-in-fbblt.c-when-memory.patch
    - viewer can send password without proper validation of X.509 certs
      (CVE-2011-1775)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-2861.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7:9:latest_ELS");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tigervnc-server-module");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'tigervnc-1.8.0-33.0.5.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-icons-1.8.0-33.0.5.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-license-1.8.0-33.0.5.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.8.0-33.0.5.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-applet-1.8.0-33.0.5.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.8.0-33.0.5.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.8.0-33.0.5.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tigervnc / tigervnc-icons / tigervnc-license / etc');
}
