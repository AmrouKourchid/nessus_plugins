#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2941-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205736);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/17");

  script_cve_id(
    "CVE-2023-42667",
    "CVE-2023-49141",
    "CVE-2024-24853",
    "CVE-2024-24980",
    "CVE-2024-25939"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2941-1");

  script_name(english:"SUSE SLES12 Security Update : ucode-intel (SUSE-SU-2024:2941-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:2941-1 advisory.

    - Intel CPU Microcode was updated to the 20240813 release (bsc#1229129)
      - CVE-2024-24853: Security updates for [INTEL-
    SA-01083](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01083.html)
      - CVE-2024-25939: Security updates for [INTEL-
    SA-01118](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01118.html)
      - CVE-2024-24980: Security updates for [INTEL-
    SA-01100](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01100.html)
      - CVE-2023-42667: Security updates for [INTEL-
    SA-01038](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01038.html)
      - CVE-2023-49141: Security updates for [INTEL-
    SA-01046](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01046.html)
      Other issues fixed:
      - Update for functional issues. Refer to [Intel Core Ultra
    Processor](https://cdrdv2.intel.com/v1/dl/getContent/792254) for details.
      - Update for functional issues. Refer to [3rd Generation Intel Xeon Processor Scalable Family
    Specification Update](https://cdrdv2.intel.com/v1/dl/getContent/637780) for details.
      - Update for functional issues. Refer to [3rd Generation Intel Xeon Scalable Processors Specification
    Update](https://cdrdv2.intel.com/v1/dl/getContent/634897) for details.
      - Update for functional issues. Refer to [2nd Generation Intel Xeon Processor Scalable Family
    Specification Update](https://cdrdv2.intel.com/v1/dl/getContent/338848) for details
      - Update for functional issues. Refer to [Intel Xeon D-2700 Processor Specification
    Update](https://cdrdv2.intel.com/v1/dl/getContent/714071) for details.
      - Update for functional issues. Refer to [Intel Xeon E-2300 Processor Specification Update
    ](https://cdrdv2.intel.com/v1/dl/getContent/709192) for details.
      - Update for functional issues. Refer to [13th Generation Intel Core Processor Specification
    Update](https://cdrdv2.intel.com/v1/dl/getContent/740518) for details.
      - Update for functional issues. Refer to [12th Generation Intel Core Processor
    Family](https://cdrdv2.intel.com/v1/dl/getContent/682436) for details.
      - Update for functional issues. Refer to [11th Gen Intel Core Processor Specification
    Update](https://cdrdv2.intel.com/v1/dl/getContent/631123) for details.
      - Update for functional issues. Refer to [10th Gen Intel Core Processor Families Specification
    Update](https://cdrdv2.intel.com/v1/dl/getContent/341079) for details.
      - Update for functional issues. Refer to [10th Generation Intel Core Processor Specification
    Update](https://cdrdv2.intel.com/v1/dl/getContent/615213) for details.
      - Update for functional issues. Refer to [8th and 9th Generation Intel Core Processor Family Spec
    Update](https://cdrdv2.intel.com/v1/dl/getContent/337346) for details.
      - Update for functional issues. Refer to [8th Generation Intel Core Processor Families Specification
    Update](https://cdrdv2.intel.com/v1/dl/getContent/338025) for details.
      - Update for functional issues. Refer to [7th and 8th Generation Intel Core Processor Specification
    Update](https://cdrdv2.intel.com/v1/dl/getContent/334663) for details.
      - Update for functional issues. Refer to [Intel Processors and Intel Core i3
    N-Series](https://cdrdv2.intel.com/v1/dl/getContent/764616) for details.
      - Update for functional issues. Refer to [Intel Atom x6000E Series, and Intel Pentium and Celeron N and
    J Series Processors for Internet of Things (IoT)
    Applications](https://cdrdv2.intel.com/v1/dl/getContent/636674) for details.
     Updated Platforms:
      | Processor      | Stepping | F-M-S/PI    | Old Ver  | New Ver  | Products
      |:---------------|:---------|:------------|:---------|:---------|:---------
      | AML-Y22        | H0       | 06-8e-09/10 | 000000f4 | 000000f6 | Core Gen8 Mobile
      | AML-Y42        | V0       | 06-8e-0c/94 | 000000fa | 000000fc | Core Gen10 Mobile
      | CFL-H          | R0       | 06-9e-0d/22 | 000000fc | 00000100 | Core Gen9 Mobile
      | CFL-H/S        | P0       | 06-9e-0c/22 | 000000f6 | 000000f8 | Core Gen9
      | CFL-H/S/E3     | U0       | 06-9e-0a/22 | 000000f6 | 000000f8 | Core Gen8 Desktop, Mobile, Xeon E
      | CFL-S          | B0       | 06-9e-0b/02 | 000000f4 | 000000f6 | Core Gen8
      | CFL-S          | P0       | 06-9e-0c/22 | 000000f6 | 000000f8 | Core Gen9 Desktop
      | CFL-U43e       | D0       | 06-8e-0a/c0 | 000000f4 | 000000f6 | Core Gen8 Mobile
      | CLX-SP         | B1       | 06-55-07/bf | 05003605 | 05003707 | Xeon Scalable Gen2
      | CML-H          | R1       | 06-a5-02/20 | 000000fa | 000000fc | Core Gen10 Mobile
      | CML-S102       | Q0       | 06-a5-05/22 | 000000fa | 000000fc | Core Gen10
      | CML-S62        | G1       | 06-a5-03/22 | 000000fa | 000000fc | Core Gen10
      | CML-U42        | V0       | 06-8e-0c/94 | 000000fa | 000000fc | Core Gen10 Mobile
      | CML-U62 V1     | A0       | 06-a6-00/80 | 000000fa | 000000fe | Core Gen10 Mobile
      | CML-U62 V2     | K1       | 06-a6-01/80 | 000000fa | 000000fc | Core Gen10 Mobile
      | CML-Y42        | V0       | 06-8e-0c/94 | 000000fa | 000000fc | Core Gen10 Mobile
      | CPX-SP         | A1       | 06-55-0b/bf | 07002802 | 07002904 | Xeon Scalable Gen3
      | EHL            | B1       | 06-96-01/01 | 00000019 | 0000001a | Pentium J6426/N6415, Celeron
    J6412/J6413/N6210/N6211, Atom x6000E
      | ICL-D          | B0       | 06-6c-01/10 | 01000290 | 010002b0 | Xeon D-17xx, D-27xx
      | ICL-U/Y        | D1       | 06-7e-05/80 | 000000c4 | 000000c6 | Core Gen10 Mobile
      | ICX-SP         | Dx/M1    | 06-6a-06/87 | 0d0003d1 | 0d0003e7 | Xeon Scalable Gen3
      | KBL-R U        | Y0       | 06-8e-0a/c0 | 000000f4 | 000000f6 | Core Gen8 Mobile
      | KBL-U23e       | J1       | 06-8e-09/c0 | 000000f4 | 000000f6 | Core Gen7 Mobile
      | KBL-U/Y        | H0       | 06-8e-09/c0 | 000000f4 | 000000f6 | Core Gen7 Mobile
      | MTL            | C-0      | 06-aa-04/e6 | 0000001c | 0000001e | Core Ultra Processor
      | RKL-S          | B0       | 06-a7-01/02 | 0000005e | 00000062 | Core Gen11
      | TGL            | B0/B1    | 06-8c-01/80 | 000000b6 | 000000b8 | Core Gen11 Mobile
      | TGL-H          | R0       | 06-8d-01/c2 | 00000050 | 00000052 | Core Gen11 Mobile
      | TGL-R          | C0       | 06-8c-02/c2 | 00000036 | 00000038 | Core Gen11 Mobile
      | WHL-U          | V0       | 06-8e-0c/94 | 000000fa | 000000fc | Core Gen8 Mobile
      | WHL-U          | W0       | 06-8e-0b/d0 | 000000f4 | 000000f6 | Core Gen8 Mobile

    - update to 20240531:
      * Update for functional issues. Refer to Intel Pentium Silver
        and Intel Celeron Processor Specification Update
      - Updated Platforms:
        | Processor      | Stepping | F-M-S/PI    | Old Ver  | New Ver  | Products
        |:---------------|:---------|:------------|:---------|:---------|:---------
        | GLK            | B0       | 06-7a-01/01 | 00000040 | 00000042 | Pentium Silver N/J5xxx, Celeron
    N/J4xxx

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229129");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036482.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-42667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25939");
  script_set_attribute(attribute:"solution", value:
"Update the affected ucode-intel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49141");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-intel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ucode-intel-20240813-140.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'ucode-intel-20240813-140.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ucode-intel');
}
