#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0901-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159161);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id(
    "CVE-2022-26125",
    "CVE-2022-26126",
    "CVE-2022-26127",
    "CVE-2022-26128",
    "CVE-2022-26129"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0901-1");

  script_name(english:"SUSE SLES15 Security Update : frr (SUSE-SU-2022:0901-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:0901-1 advisory.

  - Buffer overflow vulnerabilities exist in FRRouting through 8.1.0 due to wrong checks on the input packet
    length in isisd/isis_tlvs.c. (CVE-2022-26125)

  - Buffer overflow vulnerabilities exist in FRRouting through 8.1.0 due to the use of strdup with a non-zero-
    terminated binary string in isis_nb_notifications.c. (CVE-2022-26126)

  - A buffer overflow vulnerability exists in FRRouting through 8.1.0 due to missing a check on the input
    packet length in the babel_packet_examin function in babeld/message.c. (CVE-2022-26127)

  - A buffer overflow vulnerability exists in FRRouting through 8.1.0 due to a wrong check on the input packet
    length in the babel_packet_examin function in babeld/message.c. (CVE-2022-26128)

  - Buffer overflow vulnerabilities exist in FRRouting through 8.1.0 due to wrong checks on the subtlv length
    in the functions, parse_hello_subtlv, parse_ihu_subtlv, and parse_update_subtlv in babeld/message.c.
    (CVE-2022-26129)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26129");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010470.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd9e778f");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26129");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:frr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:frr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrr_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrcares0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrfpm_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrgrpc_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrospfapiclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrsnmp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrzmq0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmlag_pb0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'frr-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'frr-devel-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfrr0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfrr_pb0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfrrcares0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfrrfpm_pb0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfrrgrpc_pb0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfrrospfapiclient0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfrrsnmp0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfrrzmq0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libmlag_pb0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'frr-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'frr-devel-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libfrr0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libfrr_pb0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libfrrcares0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libfrrfpm_pb0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libfrrgrpc_pb0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libfrrospfapiclient0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libfrrsnmp0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libfrrzmq0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libmlag_pb0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'frr-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'frr-devel-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libfrr0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libfrr_pb0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libfrrcares0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libfrrfpm_pb0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libfrrgrpc_pb0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libfrrospfapiclient0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libfrrsnmp0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libfrrzmq0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libmlag_pb0-7.4-150300.4.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'frr-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'frr-devel-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libfrr0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libfrr_pb0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libfrrcares0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libfrrfpm_pb0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libfrrgrpc_pb0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libfrrospfapiclient0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libfrrsnmp0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libfrrzmq0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']},
    {'reference':'libmlag_pb0-7.4-150300.4.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-server-applications-release-15.4', 'sles-release-15.4']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'frr / frr-devel / libfrr0 / libfrr_pb0 / libfrrcares0 / etc');
}
