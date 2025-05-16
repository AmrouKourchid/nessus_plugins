#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4654-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(186648);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/07");

  script_cve_id(
    "CVE-2021-26345",
    "CVE-2021-46766",
    "CVE-2021-46774",
    "CVE-2022-23820",
    "CVE-2022-23830",
    "CVE-2023-20519",
    "CVE-2023-20521",
    "CVE-2023-20526",
    "CVE-2023-20533",
    "CVE-2023-20566",
    "CVE-2023-20592"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4654-1");

  script_name(english:"SUSE SLES15 Security Update : kernel-firmware (SUSE-SU-2023:4654-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:4654-1 advisory.

  - Failure to validate the value in APCB may allow a privileged attacker to tamper with the APCB token to
    force an out-of-bounds memory read potentially resulting in a denial of service. (CVE-2021-26345)

  - Improper clearing of sensitive data in the ASP Bootloader may expose secret keys to a privileged attacker
    accessing ASP SRAM, potentially leading to a loss of confidentiality. (CVE-2021-46766)

  - Insufficient DRAM address validation in System Management Unit (SMU) may allow an attacker to read/write
    from/to an invalid DRAM address, potentially resulting in denial-of-service. (CVE-2021-46774,
    CVE-2023-20533)

  - Failure to validate the AMD SMM communication buffer may allow an attacker to corrupt the SMRAM
    potentially leading to arbitrary code execution. (CVE-2022-23820)

  - SMM configuration may not be immutable, as intended, when SNP is enabled resulting in a potential limited
    loss of guest memory integrity. (CVE-2022-23830)

  - A Use-After-Free vulnerability in the management of an SNP guest context page may allow a malicious
    hypervisor to masquerade as the guest's migration agent resulting in a potential loss of guest integrity.
    (CVE-2023-20519)

  - TOCTOU in the ASP Bootloader may allow an attacker with physical access to tamper with SPI ROM records
    after memory content verification, potentially leading to loss of confidentiality or a denial of service.
    (CVE-2023-20521)

  - Insufficient input validation in the ASP Bootloader may enable a privileged attacker with physical access
    to expose the contents of ASP memory potentially leading to a loss of confidentiality. (CVE-2023-20526)

  - Improper address validation in ASP with SNP enabled may potentially allow an attacker to compromise guest
    memory integrity. (CVE-2023-20566)

  - Improper or unexpected behavior of the INVD instruction in some AMD CPUs may allow an attacker with a
    malicious hypervisor to affect cache line write-back behavior of the CPU leading to a potential loss of
    guest virtual machine (VM) memory integrity. (CVE-2023-20592)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215831");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-December/017285.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30f6ef8f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-26345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20592");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-firmware, kernel-firmware-brcm and / or ucode-amd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23820");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-brcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-amd");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-firmware-20210208-150300.4.19.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'ucode-amd-20210208-150300.4.19.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-firmware-20210208-150300.4.19.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'kernel-firmware-brcm-20210208-150300.4.19.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'ucode-amd-20210208-150300.4.19.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'kernel-firmware-20210208-150300.4.19.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-firmware-brcm-20210208-150300.4.19.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'ucode-amd-20210208-150300.4.19.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-firmware / kernel-firmware-brcm / ucode-amd');
}
