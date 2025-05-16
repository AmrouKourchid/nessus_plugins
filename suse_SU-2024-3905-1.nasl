#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3905-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(210293);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2023-50782");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3905-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : openssl-1_1 (SUSE-SU-2024:3905-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by a vulnerability as referenced in the SUSE-SU-2024:3905-1 advisory.

    Security fixes:

    - CVE-2023-50782: Implicit rejection in PKCS#1 v1.5 (bsc#1220262)

    Other fixes:

    - FIPS: AES GCM external IV implementation (bsc#1228618)
    - FIPS: Mark PBKDF2 and HKDF HMAC input keys with size >= 112 bits as approved in the SLI. (bsc#1228623)
    - FIPS: Enforce KDF in FIPS style (bsc#1224270)
    - FIPS: Mark HKDF and TLSv1.3 KDF as approved in the SLI (bsc#1228619)
    - FIPS: The X9.31 scheme is not approved for RSA signature operations in FIPS 186-5. (bsc#1224269)
    - FIPS: Differentiate the PSS length requirements (bsc#1224275)
    - FIPS: Mark sigGen and sigVer primitives as non-approved (bsc#1224272)
    - FIPS: Disable PKCSv1.5 and shake in FIPS mode (bsc#1224271)
    - FIPS: Mark SHA1 as non-approved in the SLI (bsc#1224266)
    - FIPS: DH FIPS selftest and safe prime group (bsc#1224264)
    - FIPS: Remove not needed FIPS DRBG files (bsc#1224268)
    - FIPS: Add Pair-wise Consistency Test when generating DH key (bsc#1224265)
    - FIPS: Disallow non-approved KDF types (bsc#1224267)
    - FIPS: Disallow RSA sigVer with 1024 and ECDSA sigVer/keyVer P-192 (bsc#1224273)
    - FIPS: DRBG component chaining (bsc#1224258)
    - FIPS: Align CRNGT_BUFSIZ with Jitter RNG output size (bsc#1224260)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228623");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019774.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59aeb84c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-50782");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-1_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-1_1");
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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libopenssl-1_1-devel-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libopenssl-1_1-devel-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libopenssl1_1-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libopenssl1_1-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libopenssl1_1-32bit-1.1.1w-150600.5.9.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libopenssl1_1-32bit-1.1.1w-150600.5.9.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'openssl-1_1-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libopenssl-1_1-devel-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libopenssl-1_1-devel-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libopenssl1_1-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libopenssl1_1-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libopenssl1_1-32bit-1.1.1w-150600.5.9.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libopenssl1_1-32bit-1.1.1w-150600.5.9.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'openssl-1_1-1.1.1w-150600.5.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'libopenssl-1_1-devel-1.1.1w-150600.5.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libopenssl-1_1-devel-32bit-1.1.1w-150600.5.9.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libopenssl1_1-1.1.1w-150600.5.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'libopenssl1_1-32bit-1.1.1w-150600.5.9.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'openssl-1_1-1.1.1w-150600.5.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'openssl-1_1-doc-1.1.1w-150600.5.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenssl-1_1-devel / libopenssl-1_1-devel-32bit / libopenssl1_1 / etc');
}
