#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3237-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(179591);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/09");

  script_cve_id(
    "CVE-2022-48503",
    "CVE-2023-32435",
    "CVE-2023-32439",
    "CVE-2023-38133",
    "CVE-2023-38572",
    "CVE-2023-38592",
    "CVE-2023-38594",
    "CVE-2023-38595",
    "CVE-2023-38597",
    "CVE-2023-38599",
    "CVE-2023-38600",
    "CVE-2023-38611"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/14");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3237-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : webkit2gtk3 (SUSE-SU-2023:3237-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2023:3237-1 advisory.

  - Processing web content may lead to arbitrary code execution (CVE-2022-48503)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in macOS
    Ventura 13.3, Safari 16.4, iOS 16.4 and iPadOS 16.4, iOS 15.7.7 and iPadOS 15.7.7. Processing web content
    may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively
    exploited against versions of iOS released before iOS 15.7. (CVE-2023-32435)

  - A type confusion issue was addressed with improved checks. This issue is fixed in iOS 16.5.1 and iPadOS
    16.5.1, iOS 15.7.7 and iPadOS 15.7.7, macOS Ventura 13.4.1, Safari 16.5.1. Processing maliciously crafted
    web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been
    actively exploited. (CVE-2023-32439)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may
    disclose sensitive information. (CVE-2023-38133)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. A website may be able to
    bypass Same Origin Policy. (CVE-2023-38572)

  - A logic issue was addressed with improved restrictions. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    watchOS 9.6, tvOS 16.6, macOS Ventura 13.5. Processing web content may lead to arbitrary code execution.
    (CVE-2023-38592)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may
    lead to arbitrary code execution. (CVE-2023-38594)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.6 and iPadOS 16.6, tvOS 16.6,
    macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may lead to arbitrary code execution.
    (CVE-2023-38595, CVE-2023-38600)

  - The issue was addressed with improved checks. This issue is fixed in iOS 15.7.8 and iPadOS 15.7.8, iOS
    16.6 and iPadOS 16.6, macOS Ventura 13.5, Safari 16.6. Processing web content may lead to arbitrary code
    execution. (CVE-2023-38597)

  - A logic issue was addressed with improved state management. This issue is fixed in Safari 16.6, watchOS
    9.6, iOS 15.7.8 and iPadOS 15.7.8, tvOS 16.6, iOS 16.6 and iPadOS 16.6, macOS Ventura 13.5. A website may
    be able to track sensitive user information. (CVE-2023-38599)

  - The issue was addressed with improved memory handling. This issue is fixed in iOS 16.6 and iPadOS 16.6,
    tvOS 16.6, macOS Ventura 13.5, Safari 16.6, watchOS 9.6. Processing web content may lead to arbitrary code
    execution. (CVE-2023-38611)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213905");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-August/030852.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32439");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38611");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38611");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjavascriptcoregtk-4_0-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED12|SLED_SAP12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(2|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libjavascriptcoregtk-4_0-18-2.40.5-2.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libjavascriptcoregtk-4_0-18-32bit-2.40.5-2.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libjavascriptcoregtk-4_0-18-32bit-2.40.5-2.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libwebkit2gtk-4_0-37-2.40.5-2.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libwebkit2gtk3-lang-2.40.5-2.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.40.5-2.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.40.5-2.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.40.5-2.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.40.5-2.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'webkit2gtk3-devel-2.40.5-2.146.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.40.5-2.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'webkit2gtk3-devel-2.40.5-2.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libjavascriptcoregtk-4_0-18-32bit-2.40.5-2.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libjavascriptcoregtk-4_0-18-32bit-2.40.5-2.146.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.40.5-2.146.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'libwebkit2gtk-4_0-37-2.40.5-2.146.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'libwebkit2gtk3-lang-2.40.5-2.146.1', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.40.5-2.146.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.40.5-2.146.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'typelib-1_0-WebKit2WebExtension-4_0-2.40.5-2.146.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.40.5-2.146.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'webkit2gtk3-devel-2.40.5-2.146.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'libjavascriptcoregtk-4_0-18-2.40.5-2.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libwebkit2gtk-4_0-37-2.40.5-2.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libwebkit2gtk3-lang-2.40.5-2.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'typelib-1_0-JavaScriptCore-4_0-2.40.5-2.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'typelib-1_0-WebKit2-4_0-2.40.5-2.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'webkit2gtk-4_0-injected-bundles-2.40.5-2.146.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-32bit / etc');
}
