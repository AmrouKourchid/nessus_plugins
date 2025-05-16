#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3843-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(210036);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2024-2199", "CVE-2024-3657", "CVE-2024-5953");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3843-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : 389-ds (SUSE-SU-2024:3843-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:3843-1 advisory.

    - Persist extracted key path for ldap_ssl_client_init over repeat invocations (bsc#1230852)
    - Re-enable use of .dsrc basedn for dsidm commands (bsc#1231462)
    - Update to version 2.2.10~git18.20ce9289:
      * RFE: Use previously extracted key path
      * Update dsidm to prioritize basedn from .dsrc over interactive input
      * UI: Instance fails to load when DB backup directory doesn't exist
      * Improve online import robustness when the server is under load
      * Ensure all slapi_log_err calls end format strings with newline character \n
      * RFE: when memberof is enabled, defer updates of members from the update of the group
      * Provide more information in the error message during setup_ol_tls_conn()
      * Wrong set of entries returned for some search filters
      * Schema lib389 object is not keeping custom schema data upon editing
      * UI: Fix audit issue with npm - micromatch
      * Fix long delay when setting replication agreement with dsconf
      * Changelog trims updates from a given RID even if a consumer has not received any of them
      * test_password_modify_non_utf8 should set default password storage scheme
      * Update Cargo.lock
      * Rearrange includes for 32-bit support logic
      * Fix fedora cop RawHide builds
      * Bump braces from 3.0.2 to 3.0.3 in /src/cockpit/389-console
      * Enabling replication for a sub suffix crashes browser
      * d2entry - Could not open id2entry err 0 - at startup when having sub-suffixes
      * Slow ldif2db import on a newly created BDB backend
      * Audit log buffering doesn't handle large updates
      * RFE: improve the performance of evaluation of filter component when tested against a large valueset
    (like group members)
      * passwordHistory is not updated with a pre-hashed password
      * ns-slapd crash in referint_get_config
      * Fix the UTC offset print
      * Fix OpenLDAP version autodetection
      * RFE: add new operation note for MFA authentications
      * Add log buffering to audit log
      * Fix connection timeout error breaking errormap
      * Improve dsidm CLI No Such Entry handling
      * Improve connection timeout error logging
      * Add hidden -v and -j options to each CLI subcommand
      * Fix various issues with logconv.pl
      * Fix certificate lifetime displayed as NaN
      * Enhance Rust and JS bundling and add SPDX licenses for both
      * Remove audit-ci from dependencies
      * Fix unused variable warning from previous commit
      * covscan: fix memory leak in audit log when adding entries
      * Add a check for tagged commits
      * dscreate ds-root - accepts relative path
      * Change replica_id from str to int
      * Attribute Names changed to lowercase after adding the Attributes
      * ns-slapd crashes at startup if a backend has no suffix
      * During an update, if the target entry is reverted in the entry cache, the server should not retry to
    lock it
      * Reversion of the entry cache should be limited to BETXN plugin failures
      * Disable Transparent Huge Pages
      * Freelist ordering causes high wtime
      * Security fix for CVE-2024-2199
    - VUL-0: CVE-2024-3657: 389-ds: potential denial of service via specially crafted kerberos AS-REQ request
    (bsc#1225512)
    - VUL-0: CVE-2024-5953: 389-ds: malformed userPassword hashes may cause a denial of service (bsc#1226277)
    - 389ds crash when user does change password using iso-8859-1 encoding (bsc#1228912)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231462");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-October/019746.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?899661f1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5953");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:389-ds-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lib389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsvrcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'389-ds-2.2.10~git18.20ce9289-150500.3.24.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'389-ds-devel-2.2.10~git18.20ce9289-150500.3.24.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'lib389-2.2.10~git18.20ce9289-150500.3.24.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libsvrcore0-2.2.10~git18.20ce9289-150500.3.24.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'389-ds-2.2.10~git18.20ce9289-150500.3.24.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'389-ds-devel-2.2.10~git18.20ce9289-150500.3.24.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'lib389-2.2.10~git18.20ce9289-150500.3.24.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libsvrcore0-2.2.10~git18.20ce9289-150500.3.24.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'389-ds-2.2.10~git18.20ce9289-150500.3.24.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'389-ds-devel-2.2.10~git18.20ce9289-150500.3.24.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'389-ds-snmp-2.2.10~git18.20ce9289-150500.3.24.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'lib389-2.2.10~git18.20ce9289-150500.3.24.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libsvrcore0-2.2.10~git18.20ce9289-150500.3.24.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, '389-ds / 389-ds-devel / 389-ds-snmp / lib389 / libsvrcore0');
}
