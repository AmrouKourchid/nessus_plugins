#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0783-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(191702);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id(
    "CVE-2023-4750",
    "CVE-2023-48231",
    "CVE-2023-48232",
    "CVE-2023-48233",
    "CVE-2023-48234",
    "CVE-2023-48235",
    "CVE-2023-48236",
    "CVE-2023-48237",
    "CVE-2023-48706",
    "CVE-2024-22667"
  );
  script_xref(name:"IAVB", value:"2023-B-0066-S");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0783-1");
  script_xref(name:"IAVA", value:"2023-A-0650-S");

  script_name(english:"SUSE SLES12 Security Update : vim (SUSE-SU-2024:0783-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:0783-1 advisory.

  - Use After Free in GitHub repository vim/vim prior to 9.0.1857. (CVE-2023-4750)

  - Vim is an open source command line text editor. When closing a window, vim may try to access already freed
    window structure. Exploitation beyond crashing the application has not been shown to be viable. This issue
    has been addressed in commit `25aabc2b` which has been included in release version 9.0.2106. Users are
    advised to upgrade. There are no known workarounds for this vulnerability. (CVE-2023-48231)

  - Vim is an open source command line text editor. A floating point exception may occur when calculating the
    line offset for overlong lines and smooth scrolling is enabled and the cpo-settings include the 'n' flag.
    This may happen when a window border is present and when the wrapped line continues on the next physical
    line directly in the window border because the 'cpo' setting includes the 'n' flag. Only users with non-
    default settings are affected and the exception should only result in a crash. This issue has been
    addressed in commit `cb0b99f0` which has been included in release version 9.0.2107. Users are advised to
    upgrade. There are no known workarounds for this vulnerability. (CVE-2023-48232)

  - Vim is an open source command line text editor. If the count after the :s command is larger than what fits
    into a (signed) long variable, abort with e_value_too_large. Impact is low, user interaction is required
    and a crash may not even happen in all situations. This issue has been addressed in commit `ac6378773`
    which has been included in release version 9.0.2108. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-48233)

  - Vim is an open source command line text editor. When getting the count for a normal mode z command, it may
    overflow for large counts given. Impact is low, user interaction is required and a crash may not even
    happen in all situations. This issue has been addressed in commit `58f9befca1` which has been included in
    release version 9.0.2109. Users are advised to upgrade. There are no known workarounds for this
    vulnerability. (CVE-2023-48234)

  - Vim is an open source command line text editor. When parsing relative ex addresses one may unintentionally
    cause an overflow. Ironically this happens in the existing overflow check, because the line number becomes
    negative and LONG_MAX - lnum will cause the overflow. Impact is low, user interaction is required and a
    crash may not even happen in all situations. This issue has been addressed in commit `060623e` which has
    been included in release version 9.0.2110. Users are advised to upgrade. There are no known workarounds
    for this vulnerability. (CVE-2023-48235)

  - Vim is an open source command line text editor. When using the z= command, the user may overflow the count
    with values larger than MAX_INT. Impact is low, user interaction is required and a crash may not even
    happen in all situations. This vulnerability has been addressed in commit `73b2d379` which has been
    included in release version 9.0.2111. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2023-48236)

  - Vim is an open source command line text editor. In affected versions when shifting lines in operator
    pending mode and using a very large value, it may be possible to overflow the size of integer. Impact is
    low, user interaction is required and a crash may not even happen in all situations. This issue has been
    addressed in commit `6bf131888` which has been included in version 9.0.2112. Users are advised to upgrade.
    There are no known workarounds for this vulnerability. (CVE-2023-48237)

  - Vim is a UNIX editor that, prior to version 9.0.2121, has a heap-use-after-free vulnerability. When
    executing a `:s` command for the very first time and using a sub-replace-special atom inside the
    substitution part, it is possible that the recursive `:s` call causes free-ing of memory which may later
    then be accessed by the initial `:s` command. The user must intentionally execute the payload and the
    whole process is a bit tricky to do since it seems to work only reliably for the very first :s command. It
    may also cause a crash of Vim. Version 9.0.2121 contains a fix for this issue. (CVE-2023-48706)

  - Vim before 9.0.2142 has a stack-based buffer overflow because did_set_langmap in map.c calls sprintf to
    write to the error buffer that is passed down to the option callback functions. (CVE-2024-22667)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219581");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-March/018104.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1c263b9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48231");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22667");
  script_set_attribute(attribute:"solution", value:
"Update the affected gvim, vim, vim-data and / or vim-data-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22667");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim-data-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'gvim-9.1.0111-17.29.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'vim-9.1.0111-17.29.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'vim-data-9.1.0111-17.29.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'vim-data-common-9.1.0111-17.29.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'gvim-9.1.0111-17.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'vim-9.1.0111-17.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'vim-data-9.1.0111-17.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'vim-data-common-9.1.0111-17.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gvim / vim / vim-data / vim-data-common');
}
