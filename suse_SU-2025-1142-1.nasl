#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1142-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(233885);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/05");

  script_cve_id("CVE-2024-45337");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1142-1");

  script_name(english:"SUSE SLES12 Security Update : google-guest-agent (SUSE-SU-2025:1142-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has a package installed that is affected by a vulnerability as referenced
in the SUSE-SU-2025:1142-1 advisory.

    - CVE-2024-45337: golang.org/x/crypto/ssh: Fixed misuse of ServerConfig.PublicKeyCallback leading to
    authorization bypass (bsc#1234563).

    Other fixes:
    - Updated to version 20250327.01 (bsc#1239763, bsc#1239866)
      * Remove error messages from gce_workload_cert_refresh and
        metadata script runner (#527)
    - from version 20250327.00
      * Update guest-logging-go dependency (#526)
      * Add 'created-by' metadata, and pass it as option to logging library (#508)
      * Revert 'oslogin: Correctly handle newlines at the end of
        modified files (#520)' (#523)
      * Re-enable disabled services if the core plugin was enabled (#522)
      * Enable guest services on package upgrade (#519)
      * oslogin: Correctly handle newlines at the end of modified files (#520)
      * Fix core plugin path (#518)
      * Fix package build issues (#517)
      * Fix dependencies ran go mod tidy -v (#515)
      * Fix debian build path (#514)
      * Bundle compat metadata script runner binary in package (#513)
      * Bump golang.org/x/net from 0.27.0 to 0.36.0 (#512)
      * Update startup/shutdown services to launch compat manager (#503)
      * Bundle new gce metadata script runner binary in agent package (#502)
      * Revert 'Revert bundling new binaries in the package (#509)' (#511)
    - from version 20250326.00
      * Re-enable disabled services if the core plugin was enabled (#521)
    - from version 20250324.00
      * Enable guest services on package upgrade (#519)
      * oslogin: Correctly handle newlines at the end of modified files (#520)
      * Fix core plugin path (#518)
      * Fix package build issues (#517)
      * Fix dependencies ran go mod tidy -v (#515)
      * Fix debian build path (#514)
      * Bundle compat metadata script runner binary in package (#513)
      * Bump golang.org/x/net from 0.27.0 to 0.36.0 (#512)
      * Update startup/shutdown services to launch compat manager (#503)
      * Bundle new gce metadata script runner binary in agent package (#502)
      * Revert 'Revert bundling new binaries in the package (#509)' (#511)
      * Revert bundling new binaries in the package (#509)
      * Fix typo in windows build script (#501)
      * Include core plugin binary for all packages (#500)
      * Start packaging compat manager (#498)
      * Start bundling ggactl_plugin_cleanup binary in all agent packages (#492)
      * scripts: introduce a wrapper to locally build deb package (#490)
      * Introduce compat-manager systemd unit (#497)
    - from version 20250317.00
      * Revert 'Revert bundling new binaries in the package (#509)' (#511)
      * Revert bundling new binaries in the package (#509)
      * Fix typo in windows build script (#501)
      * Include core plugin binary for all packages (#500)
      * Start packaging compat manager (#498)
      * Start bundling ggactl_plugin_cleanup binary in all agent packages (#492)
      * scripts: introduce a wrapper to locally build deb package (#490)
      * Introduce compat-manager systemd unit (#497)
    - from version 20250312.00
      * Revert bundling new binaries in the package (#509)
      * Fix typo in windows build script (#501)
      * Include core plugin binary for all packages (#500)
      * Start packaging compat manager (#498)
      * Start bundling ggactl_plugin_cleanup binary in all agent packages (#492)
      * scripts: introduce a wrapper to locally build deb package (#490)
      * Introduce compat-manager systemd unit (#497)
    - from version 20250305.00
      * Revert bundling new binaries in the package (#509)
      * Fix typo in windows build script (#501)
      * Include core plugin binary for all packages (#500)
      * Start packaging compat manager (#498)
      * Start bundling ggactl_plugin_cleanup binary in all agent packages (#492)
      * scripts: introduce a wrapper to locally build deb package (#490)
      * Introduce compat-manager systemd unit (#497)
    - from version 20250304.01
      * Fix typo in windows build script (#501)
    - from version 20250214.01
      * Include core plugin binary for all packages (#500)
    - from version 20250212.00
      * Start packaging compat manager (#498)
      * Start bundling ggactl_plugin_cleanup binary in all agent packages (#492)
    - from version 20250211.00
      * scripts: introduce a wrapper to locally build deb package (#490)
      * Introduce compat-manager systemd unit (#497)
    - from version 20250207.00
      * vlan: toggle vlan configuration in debian packaging (#495)
      * vlan: move config out of unstable section (#494)
      * Add clarification to comments regarding invalid NICs and the
        `invalid` tag. (#493)
      * Include interfaces in lists even if it has an invalid MAC. (#489)
      * Fix windows package build failures (#491)
      * vlan: don't index based on the vlan ID (#486)
      * Revert PR #482 (#488)
      * Remove Amy and Zach from OWNERS (#487)
      * Skip interfaces in interfaceNames() instead of erroring if there is an (#482)
      * Fix Debian packaging if guest agent manager is not checked out (#485)
    - from version 20250204.02
      * force concourse to move version forward.
    - from version 20250204.01
      * vlan: toggle vlan configuration in debian packaging (#495)
    - from version 20250204.00
      * vlan: move config out of unstable section (#494)
      * Add clarification to comments regarding invalid NICs and the
        `invalid` tag. (#493)
    - from version 20250203.01
      * Include interfaces in lists even if it has an invalid MAC. (#489)
    - from version 20250203.00
      * Fix windows package build failures (#491)
      * vlan: don't index based on the vlan ID (#486)
      * Revert PR #482 (#488)
      * Remove Amy and Zach from OWNERS (#487)
      * Skip interfaces in interfaceNames() instead of erroring if there is an (#482)
      * Fix Debian packaging if guest agent manager is not checked out (#485)
    - from version 20250122.00
      * networkd(vlan): remove the interface in addition to config (#468)
      * Implement support for vlan dynamic removal, update dhclient to
        remove only if configured (#465)
      * Update logging library (#479)
      * Remove Pat from owners file. (#478)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239866");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038915.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45337");
  script_set_attribute(attribute:"solution", value:
"Update the affected google-guest-agent package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45337");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:google-guest-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP0/3/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(0|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP0/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'google-guest-agent-20250327.01-1.50.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'google-guest-agent-20250327.01-1.50.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'google-guest-agent-20250327.01-1.50.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'google-guest-agent-20250327.01-1.50.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'google-guest-agent-20250327.01-1.50.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-public-cloud-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'google-guest-agent-20250327.01-1.50.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-public-cloud-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'google-guest-agent-20250327.01-1.50.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-public-cloud-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'google-guest-agent-20250327.01-1.50.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-public-cloud-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'google-guest-agent');
}
