#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0733-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216900);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

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
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0733-1");
  script_xref(name:"IAVA", value:"2025-A-0135");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : xorg-x11-server (SUSE-SU-2025:0733-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2025:0733-1 advisory.

    - CVE-2025-26594: Use-after-free of the root cursor (bsc#1237427).
    - CVE-2025-26595: Buffer overflow in XkbVModMaskText() (bsc#1237429).
    - CVE-2025-26596: Heap overflow in XkbWriteKeySyms() (bsc#1237430).
    - CVE-2025-26597: Buffer overflow in XkbChangeTypesOfKey() (bsc#1237431).
    - CVE-2025-26598: Out-of-bounds write in CreatePointerBarrierClient() (bsc#1237432).
    - CVE-2025-26599: Use of uninitialized pointer in compRedirectWindow() (bsc#1237433).
    - CVE-2025-26600: Use-after-free in PlayReleasedEvents() (bsc#1237434).
    - CVE-2025-26601: Use-after-free in SyncInitTrigger() (bsc#1237435).

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237435");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020438.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c232447c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-26594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-26595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-26596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-26597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-26598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-26599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-26600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-26601");
  script_set_attribute(attribute:"solution", value:
"Update the affected xorg-x11-server, xorg-x11-server-extra, xorg-x11-server-sdk and / or xorg-x11-server-wayland
packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xorg-x11-server-wayland");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'xorg-x11-server-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'xorg-x11-server-extra-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'xorg-x11-server-sdk-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'xorg-x11-server-wayland-1.20.3-150200.22.5.102.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'xorg-x11-server-wayland-1.20.3-150200.22.5.102.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'xorg-x11-server-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'xorg-x11-server-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'xorg-x11-server-extra-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'xorg-x11-server-extra-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'xorg-x11-server-sdk-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'xorg-x11-server-sdk-1.20.3-150200.22.5.102.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'xorg-x11-server-wayland-1.20.3-150200.22.5.102.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'xorg-x11-server-wayland-1.20.3-150200.22.5.102.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'xorg-x11-server-1.20.3-150200.22.5.102.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'xorg-x11-server-extra-1.20.3-150200.22.5.102.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'xorg-x11-server-sdk-1.20.3-150200.22.5.102.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xorg-x11-server / xorg-x11-server-extra / xorg-x11-server-sdk / etc');
}
