#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2910-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205578);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/15");

  script_cve_id("CVE-2024-2199", "CVE-2024-3657", "CVE-2024-5953");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2910-1");

  script_name(english:"SUSE SLES15 Security Update : 389-ds (SUSE-SU-2024:2910-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:2910-1 advisory.

    Security issues fixed:

    - CVE-2024-3657: Fixed potential denial of service via specially crafted kerberos AS-REQ request
    (bsc#1225512)
    - CVE-2024-5953: Fixed a denial of service caused by malformed userPassword hashes (bsc#1226277)
    - CVE-2024-2199: Fixed a crash caused by malformed userPassword in do_modify() (bsc#1225507)

    Non-security issues fixed:

    - crash when user does change password using iso-8859-1 encoding (bsc#1228912)

    - Update to version 2.2.10:

      Issue 2324 - Add a CI test (#6289)
      Issue 6284 - BUG - freelist ordering causes high wtime
      Issue 5327 - Fix test metadata
      Issue 5853 - Update Cargo.lock
      Issue 5962 - Rearrange includes for 32-bit support logic
      Issue 5973 - Fix fedora cop RawHide builds (#5974)
      Bump braces from 3.0.2 to 3.0.3 in /src/cockpit/389-console
      Issue 6254 - Enabling replication for a sub suffix crashes browser (#6255)
      Issue 6224 - d2entry - Could not open id2entry err 0 - at startup when having sub-suffixes (#6225)
      Issue 6183 - Slow ldif2db import on a newly created BDB backend (#6208)
      Issue 6170 - audit log buffering doesn't handle large updates
      Issue 6193 - Test failure: test_tls_command_returns_error_text
      Issue 6189 - CI tests fail with `[Errno 2] No such file or directory:
    '/var/cache/dnf/metadata_lock.pid'`
      Issue 6172 - RFE: improve the performance of evaluation of filter component when tested against a large
    valueset (like group members) (#6173)
      Issue 6092 - passwordHistory is not updated with a pre-hashed password (#6093)
      Issue 6080 - ns-slapd crash in referint_get_config (#6081)
      Issue 6117 - Fix the UTC offset print (#6118)
      Issue 5305 - OpenLDAP version autodetection doesn't work
      Issue 6112 - RFE - add new operation note for MFA authentications
      Issue 5842 - Add log buffering to audit log
      Issue 6103 - New connection timeout error breaks errormap (#6104)
      Issue 6067 - Improve dsidm CLI No Such Entry handling (#6079)
      Issue 6096 - Improve connection timeout error logging (#6097)
      Issue 6067 - Add hidden -v and -j options to each CLI subcommand (#6088)
      Issue 5487 - Fix various isses with logconv.pl (#6085)
      Issue 6052 - Paged results test sets hostname to `localhost` on test collection
      Issue 6061 - Certificate lifetime displayed as NaN
      Issue 6043, 6044 - Enhance Rust and JS bundling and add SPDX licenses for both (#6045)
      Issue 3555 - Remove audit-ci from dependencies (#6056)
      Issue 5647 - Fix unused variable warning from previous commit (#5670)
      issue 5647 - covscan: memory leak in audit log when adding entries (#5650)
      Issue 6047 - Add a check for tagged commits
      Issue 6041 - dscreate ds-root - accepts relative path (#6042)
      Issue 6034 - Change replica_id from str to int
      Issue 5938 - Attribute Names changed to lowercase after adding the Attributes (#5940)
      Issue 5870 - ns-slapd crashes at startup if a backend has no suffix (#5871)
      Issue 5939 - During an update, if the target entry is reverted in the entry cache, the server should not
    retry to lock it (#6007)
      Issue 5944 - Reversion of the entry cache should be limited to BETXN plugin failures (#5994)
      Issue 5954 - Disable Transparent Huge Pages

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228912");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-August/019198.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18c4c53f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5953");
  script_set_attribute(attribute:"solution", value:
"Update the affected 389-ds, 389-ds-devel, lib389 and / or libsvrcore0 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'389-ds-2.2.10~git2.345056d3-150600.8.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'389-ds-devel-2.2.10~git2.345056d3-150600.8.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'lib389-2.2.10~git2.345056d3-150600.8.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libsvrcore0-2.2.10~git2.345056d3-150600.8.7.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'389-ds-2.2.10~git2.345056d3-150600.8.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'389-ds-devel-2.2.10~git2.345056d3-150600.8.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'lib389-2.2.10~git2.345056d3-150600.8.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']},
    {'reference':'libsvrcore0-2.2.10~git2.345056d3-150600.8.7.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-server-applications-release-15.6', 'sles-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, '389-ds / 389-ds-devel / lib389 / libsvrcore0');
}
