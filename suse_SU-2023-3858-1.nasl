#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3858-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(182184);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/12");

  script_cve_id("CVE-2020-35357");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3858-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : gsl (SUSE-SU-2023:3858-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by a vulnerability as referenced in the SUSE-SU-2023:3858-1 advisory.

  - A buffer overflow can occur when calculating the quantile value using the Statistics Library of GSL (GNU
    Scientific Library), versions 2.5 and 2.6. Processing a maliciously crafted input data for
    gsl_stats_quantile_from_sorted_data of the library may lead to unexpected application termination or
    arbitrary code execution. (CVE-2020-35357)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214681");
  # https://lists.suse.com/pipermail/sle-updates/2023-September/031799.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a26ae2e3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35357");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35357");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gsl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsl25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgslcblas0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'gsl-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl-doc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl-examples-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl-gnu-hpc-devel-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl-gnu-hpc-doc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl_2_6-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl_2_6-gnu-hpc-devel-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl_2_6-gnu-hpc-doc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl_2_6-gnu-hpc-examples-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl_2_6-gnu-hpc-module-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libgsl-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libgsl_2_6-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libgslcblas-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libgslcblas_2_6-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gsl-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl-devel-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl-doc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl-examples-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl-gnu-hpc-devel-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl-gnu-hpc-doc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl_2_6-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl_2_6-gnu-hpc-devel-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl_2_6-gnu-hpc-doc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl_2_6-gnu-hpc-examples-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gsl_2_6-gnu-hpc-module-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libgsl-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libgsl25-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libgsl_2_6-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libgslcblas-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libgslcblas0-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libgslcblas_2_6-gnu-hpc-2.6-150200.3.4.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gsl / gsl-devel / gsl-doc / gsl-examples / gsl-gnu-hpc / etc');
}
