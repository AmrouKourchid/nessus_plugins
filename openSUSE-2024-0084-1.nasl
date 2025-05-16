#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0084-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(192233);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2024-1669",
    "CVE-2024-1670",
    "CVE-2024-1671",
    "CVE-2024-1672",
    "CVE-2024-1673",
    "CVE-2024-1674",
    "CVE-2024-1675",
    "CVE-2024-1676",
    "CVE-2024-2173",
    "CVE-2024-2174",
    "CVE-2024-2176",
    "CVE-2024-2400"
  );

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2024:0084-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0084-1 advisory.

  - Out of bounds memory access in Blink in Google Chrome prior to 122.0.6261.57 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-1669)

  - Use after free in Mojo in Google Chrome prior to 122.0.6261.57 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-1670)

  - Inappropriate implementation in Site Isolation in Google Chrome prior to 122.0.6261.57 allowed a remote
    attacker to bypass content security policy via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-1671)

  - Inappropriate implementation in Content Security Policy in Google Chrome prior to 122.0.6261.57 allowed a
    remote attacker to bypass content security policy via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2024-1672)

  - Use after free in Accessibility in Google Chrome prior to 122.0.6261.57 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via specific UI gestures.
    (Chromium security severity: Medium) (CVE-2024-1673)

  - Inappropriate implementation in Navigation in Google Chrome prior to 122.0.6261.57 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-1674)

  - Insufficient policy enforcement in Download in Google Chrome prior to 122.0.6261.57 allowed a remote
    attacker to bypass filesystem restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-1675)

  - Inappropriate implementation in Navigation in Google Chrome prior to 122.0.6261.57 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-1676)

  - Out of bounds memory access in V8 in Google Chrome prior to 122.0.6261.111 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-2173)

  - Inappropriate implementation in V8 in Google Chrome prior to 122.0.6261.111 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-2174)

  - Use after free in FedCM in Google Chrome prior to 122.0.6261.111 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2176)

  - Use after free in Performance Manager in Google Chrome prior to 122.0.6261.128 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-2400)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221335");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2LA5F4J2SLVEY6FKG6O3LFDSA2N3OMZH/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c96ee03e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2174");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2400");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2400");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clang17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clang17-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libLLVM17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libLLVM17-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libLLVM17-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libLTO17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclang-cpp17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclang-cpp17-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclang-cpp17-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblldb17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libomp17-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lld17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lldb17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lldb17-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-libc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-libc++1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-libc++abi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-libc++abi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-libclang13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-opt-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-polly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-polly-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:llvm17-vim-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-clang17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-lldb17");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-122.0.6261.128-bp155.2.75.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-122.0.6261.128-bp155.2.75.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-122.0.6261.128-bp155.2.75.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-122.0.6261.128-bp155.2.75.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang17-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang17-devel-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libLLVM17-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libLLVM17-32bit-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libLLVM17-64bit-17.0.6-bp155.2.2', 'cpu':'aarch64_ilp32', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libLTO17-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libclang-cpp17-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libclang-cpp17-32bit-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libclang-cpp17-64bit-17.0.6-bp155.2.2', 'cpu':'aarch64_ilp32', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblldb17-17.0.6-bp155.2.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblldb17-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp17-devel-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld17-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb17-17.0.6-bp155.2.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb17-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb17-devel-17.0.6-bp155.2.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb17-devel-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-devel-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-gold-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libc++-devel-17.0.6-bp155.2.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libc++-devel-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libc++1-17.0.6-bp155.2.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libc++1-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libc++abi-devel-17.0.6-bp155.2.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libc++abi-devel-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libc++abi1-17.0.6-bp155.2.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libc++abi1-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-libclang13-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-opt-viewer-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-polly-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-polly-devel-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm17-vim-plugins-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-clang17-17.0.6-bp155.2.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-lldb17-17.0.6-bp155.2.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-lldb17-17.0.6-bp155.2.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium / clang17 / clang17-devel / libLLVM17 / etc');
}
