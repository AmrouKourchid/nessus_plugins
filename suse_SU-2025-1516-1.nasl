#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1516-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(235636);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2024-6119");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1516-1");

  script_name(english:"SUSE SLES15 Security Update : openssl-3 (SUSE-SU-2025:1516-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by a vulnerability as referenced in the SUSE-
SU-2025:1516-1 advisory.

    - CVE-2024-6119: Fixed denial of service in X.509 name checks (bsc#1229465)

    Other fixes:

    - FIPS: Deny SHA-1 signature verification in FIPS provider (bsc#1221365).
    - FIPS: RSA keygen PCT requirements.
    - FIPS: Check that the fips provider is available before setting
      it as the default provider in FIPS mode (bsc#1220523).
    - FIPS: Port openssl to use jitterentropy (bsc#1220523).
    - FIPS: Block non-Approved Elliptic Curves (bsc#1221786).
    - FIPS: Service Level Indicator (bsc#1221365).
    - FIPS: Output the FIPS-validation name and module version which uniquely
      identify the FIPS validated module (bsc#1221751).
    - FIPS: Add required selftests: (bsc#1221760).
    - FIPS: DH: Disable FIPS 186-4 Domain Parameters (bsc#1221821).
    - FIPS: Recommendation for Password-Based Key Derivation (bsc#1221827).
    - FIPS: Zero initialization required (bsc#1221752).
    - FIPS: Reseed DRBG (bsc#1220690, bsc#1220693, bsc#1220696).
    - FIPS: NIST SP 800-56Brev2 (bsc#1221824).
    - FIPS: Approved Modulus Sizes for RSA Digital Signature for FIPS 186-4 (bsc#1221787).
    - FIPS: Port openssl to use jitterentropy (bsc#1220523).
    - FIPS: NIST SP 800-56Arev3 (bsc#1221822).
    - FIPS: Error state has to be enforced (bsc#1221753).

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229465");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039185.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6119");
  script_set_attribute(attribute:"solution", value:
"Update the affected libopenssl-3-fips-provider package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-3-fips-provider");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(7)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP7", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libopenssl-3-fips-provider-3.1.4-150600.5.15.1', 'sp':'7', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-certifications-release-15.7']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenssl-3-fips-provider');
}
