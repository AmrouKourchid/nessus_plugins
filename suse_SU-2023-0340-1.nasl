#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0340-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171423);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id(
    "CVE-2022-23468",
    "CVE-2022-23479",
    "CVE-2022-23480",
    "CVE-2022-23481",
    "CVE-2022-23482",
    "CVE-2022-23483",
    "CVE-2022-23484"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0340-1");

  script_name(english:"SUSE SLES12 Security Update : xrdp (SUSE-SU-2023:0340-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:0340-1 advisory.

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in xrdp_login_wnd_create() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23468)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in xrdp_mm_chan_data_in() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23479)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a buffer over flow in
    devredir_proc_client_devlist_announce_req() function. There are no known workarounds for this issue. Users
    are advised to upgrade. (CVE-2022-23480)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in xrdp_caps_process_confirm_active()
    function. There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23481)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in xrdp_sec_process_mcs_data_CS_CORE()
    function. There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23482)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Out of Bound Read in libxrdp_send_to_channel() function.
    There are no known workarounds for this issue. Users are advised to upgrade. (CVE-2022-23483)

  - xrdp is an open source project which provides a graphical login to remote machines using Microsoft Remote
    Desktop Protocol (RDP). xrdp < v0.9.21 contain a Integer Overflow in
    xrdp_mm_process_rail_update_window_text() function. There are no known workarounds for this issue. Users
    are advised to upgrade. (CVE-2022-23484)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23484");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-February/013721.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6561ee66");
  script_set_attribute(attribute:"solution", value:
"Update the affected xrdp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xrdp");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'xrdp-0.9.0~git.1456906198.f422461-21.30.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'xrdp-0.9.0~git.1456906198.f422461-21.30.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xrdp');
}
