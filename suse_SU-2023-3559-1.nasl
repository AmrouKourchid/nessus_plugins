#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3559-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181257);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/25");

  script_cve_id(
    "CVE-2023-4051",
    "CVE-2023-4053",
    "CVE-2023-4574",
    "CVE-2023-4575",
    "CVE-2023-4576",
    "CVE-2023-4577",
    "CVE-2023-4578",
    "CVE-2023-4580",
    "CVE-2023-4581",
    "CVE-2023-4582",
    "CVE-2023-4583",
    "CVE-2023-4584",
    "CVE-2023-4585"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3559-1");

  script_name(english:"SUSE SLES12 Security Update : MozillaFirefox (SUSE-SU-2023:3559-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:3559-1 advisory.

  - A website could have obscured the full screen notification by using the file open dialog. This could have
    led to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 116, Firefox ESR
    < 115.2, and Thunderbird < 115.2. (CVE-2023-4051)

  - A website could have obscured the full screen notification by using a URL with a scheme handled by an
    external program, such as a mailto URL. This could have led to user confusion and possible spoofing
    attacks. This vulnerability affects Firefox < 116, Firefox ESR < 115.2, and Thunderbird < 115.2.
    (CVE-2023-4053)

  - When creating a callback over IPC for showing the Color Picker window, multiple of the same callbacks
    could have been created at a time and eventually all simultaneously destroyed as soon as one of the
    callbacks finished. This could have led to a use-after-free causing a potentially exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 102.15, Firefox ESR < 115.2, and Thunderbird < 115.2.
    (CVE-2023-4574)

  - When creating a callback over IPC for showing the File Picker window, multiple of the same callbacks could
    have been created at a time and eventually all simultaneously destroyed as soon as one of the callbacks
    finished. This could have led to a use-after-free causing a potentially exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 102.15, Firefox ESR < 115.2, and Thunderbird < 115.2.
    (CVE-2023-4575)

  - On Windows, an integer overflow could occur in `RecordedSourceSurfaceCreation` which resulted in a heap
    buffer overflow potentially leaking sensitive data that could have led to a sandbox escape. *This bug only
    affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, and Thunderbird < 115.2. (CVE-2023-4576)

  - When `UpdateRegExpStatics` attempted to access `initialStringHeap` it could already have been garbage
    collected prior to entering the function, which could potentially have led to an exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 115.2, and Thunderbird < 115.2. (CVE-2023-4577)

  - When calling `JS::CheckRegExpSyntax` a Syntax Error could have been set which would end in calling
    `convertToRuntimeErrorAndClear`. A path in the function could attempt to allocate memory when none is
    available which would have caused a newly created Out of Memory exception to be mishandled as a Syntax
    Error. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and Thunderbird < 115.2.
    (CVE-2023-4578)

  - Push notifications stored on disk in private browsing mode were not being encrypted potentially allowing
    the leak of sensitive information. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and
    Thunderbird < 115.2. (CVE-2023-4580)

  - Excel `.xll` add-in files did not have a blocklist entry in Firefox's executable blocklist which allowed
    them to be downloaded without any warning of their potential harm. This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, and Thunderbird < 115.2. (CVE-2023-4581)

  - Due to large allocation checks in Angle for glsl shaders being too lenient a buffer overflow could have
    occured when allocating too much private shader memory on mac OS. *This bug only affects Firefox on macOS.
    Other operating systems are unaffected.* This vulnerability affects Firefox < 117, Firefox ESR < 115.2,
    and Thunderbird < 115.2. (CVE-2023-4582)

  - When checking if the Browsing Context had been discarded in `HttpBaseChannel`, if the load group was not
    available then it was assumed to have already been discarded which was not always the case for private
    channels after the private session had ended. This vulnerability affects Firefox < 117, Firefox ESR <
    115.2, and Thunderbird < 115.2. (CVE-2023-4583)

  - Memory safety bugs present in Firefox 116, Firefox ESR 102.14, Firefox ESR 115.1, Thunderbird 102.14, and
    Thunderbird 115.1. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, and Thunderbird < 115.2. (CVE-2023-4584)

  - Memory safety bugs present in Firefox 116, Firefox ESR 115.1, and Thunderbird 115.1. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and
    Thunderbird < 115.2. (CVE-2023-4585)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214606");
  # https://lists.suse.com/pipermail/sle-updates/2023-September/031378.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86f48f5d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4585");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel and / or MozillaFirefox-translations-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
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
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-115.2.0-112.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-devel-115.2.0-112.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-115.2.0-112.176.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'MozillaFirefox-devel-115.2.0-112.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'MozillaFirefox-115.2.0-112.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'MozillaFirefox-translations-common-115.2.0-112.176.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-devel / etc');
}
