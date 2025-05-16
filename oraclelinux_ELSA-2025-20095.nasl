#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-20095.
##

include('compat.inc');

if (description)
{
  script_id(215966);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2024-26595",
    "CVE-2024-38538",
    "CVE-2024-38556",
    "CVE-2024-39494",
    "CVE-2024-40906",
    "CVE-2024-40939",
    "CVE-2024-41080",
    "CVE-2024-42073",
    "CVE-2024-42138",
    "CVE-2024-42268",
    "CVE-2024-42315",
    "CVE-2024-43864",
    "CVE-2024-44940",
    "CVE-2024-44949",
    "CVE-2024-46809",
    "CVE-2024-46841",
    "CVE-2024-46871",
    "CVE-2024-47730",
    "CVE-2024-49950",
    "CVE-2024-49974",
    "CVE-2024-49996",
    "CVE-2024-49998",
    "CVE-2024-50036",
    "CVE-2024-50055",
    "CVE-2024-50121",
    "CVE-2024-50241",
    "CVE-2024-50261",
    "CVE-2024-50264",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50268",
    "CVE-2024-50269",
    "CVE-2024-50273",
    "CVE-2024-50275",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50282",
    "CVE-2024-50283",
    "CVE-2024-50287",
    "CVE-2024-50290",
    "CVE-2024-50292",
    "CVE-2024-50295",
    "CVE-2024-50296",
    "CVE-2024-50299",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-53052",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53073",
    "CVE-2024-53088",
    "CVE-2024-53096",
    "CVE-2024-53099",
    "CVE-2024-53101",
    "CVE-2024-53103",
    "CVE-2024-53104",
    "CVE-2024-53112",
    "CVE-2024-53113",
    "CVE-2024-53119",
    "CVE-2024-53120",
    "CVE-2024-53122",
    "CVE-2024-53125",
    "CVE-2024-53129",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53135",
    "CVE-2024-53140",
    "CVE-2024-53141",
    "CVE-2024-53142",
    "CVE-2024-53145",
    "CVE-2024-53146",
    "CVE-2024-53148",
    "CVE-2024-53150",
    "CVE-2024-53151",
    "CVE-2024-53155",
    "CVE-2024-53156",
    "CVE-2024-53157",
    "CVE-2024-53158",
    "CVE-2024-53161",
    "CVE-2024-53164",
    "CVE-2024-53165",
    "CVE-2024-53171",
    "CVE-2024-53172",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53180",
    "CVE-2024-53181",
    "CVE-2024-53183",
    "CVE-2024-53184",
    "CVE-2024-53194",
    "CVE-2024-53197",
    "CVE-2024-53198",
    "CVE-2024-53214",
    "CVE-2024-53215",
    "CVE-2024-53217",
    "CVE-2024-53227",
    "CVE-2024-53237",
    "CVE-2024-53239",
    "CVE-2024-53240",
    "CVE-2024-53241",
    "CVE-2024-56531",
    "CVE-2024-56532",
    "CVE-2024-56533",
    "CVE-2024-56539",
    "CVE-2024-56548",
    "CVE-2024-56558",
    "CVE-2024-56562",
    "CVE-2024-56567",
    "CVE-2024-56568",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56571",
    "CVE-2024-56572",
    "CVE-2024-56574",
    "CVE-2024-56575",
    "CVE-2024-56576",
    "CVE-2024-56578",
    "CVE-2024-56581",
    "CVE-2024-56586",
    "CVE-2024-56587",
    "CVE-2024-56589",
    "CVE-2024-56590",
    "CVE-2024-56593",
    "CVE-2024-56594",
    "CVE-2024-56595",
    "CVE-2024-56596",
    "CVE-2024-56597",
    "CVE-2024-56598",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56602",
    "CVE-2024-56603",
    "CVE-2024-56605",
    "CVE-2024-56606",
    "CVE-2024-56610",
    "CVE-2024-56614",
    "CVE-2024-56615",
    "CVE-2024-56616",
    "CVE-2024-56619",
    "CVE-2024-56622",
    "CVE-2024-56623",
    "CVE-2024-56626",
    "CVE-2024-56627",
    "CVE-2024-56629",
    "CVE-2024-56630",
    "CVE-2024-56633",
    "CVE-2024-56634",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56640",
    "CVE-2024-56642",
    "CVE-2024-56643",
    "CVE-2024-56644",
    "CVE-2024-56648",
    "CVE-2024-56650",
    "CVE-2024-56659",
    "CVE-2024-56661",
    "CVE-2024-56662",
    "CVE-2024-56670",
    "CVE-2024-56679",
    "CVE-2024-56681",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56691",
    "CVE-2024-56693",
    "CVE-2024-56694",
    "CVE-2024-56698",
    "CVE-2024-56700",
    "CVE-2024-56701",
    "CVE-2024-56704",
    "CVE-2024-56705",
    "CVE-2024-56708",
    "CVE-2024-56715",
    "CVE-2024-56716",
    "CVE-2024-56723",
    "CVE-2024-56724",
    "CVE-2024-56726",
    "CVE-2024-56728",
    "CVE-2024-56739",
    "CVE-2024-56741",
    "CVE-2024-56745",
    "CVE-2024-56746",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56754",
    "CVE-2024-56756",
    "CVE-2024-56759",
    "CVE-2024-56763",
    "CVE-2024-56766",
    "CVE-2024-56767",
    "CVE-2024-56769"
  );
  script_xref(name:"IAVA", value:"2024-A-0487");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");

  script_name(english:"Oracle Linux 8 / 9 : Unbreakable Enterprise kernel (ELSA-2025-20095)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2025-20095 advisory.

    - macsec: Fix use-after-free while sending the offloading packet (Jianbo Liu)  [Orabug: 37268700]
    {CVE-2024-50261}
    - net/mlx5e: Fix CT entry update leaks of modify header context (Chris Mi)  [Orabug: 36948578]
    {CVE-2024-43864}
    - net/mlx5: Fix missing lock on sync reset reload (Moshe Shemesh)  [Orabug: 36948578] {CVE-2024-42268}
    - mlxsw: core_linecards: Fix double memory deallocation in case of invalid INI file (Aleksandr Mishin)
    [Orabug: 36948578] {CVE-2024-42138}
    - mlxsw: spectrum_buffers: Fix memory corruptions on Spectrum-4 systems (Ido Schimmel)  [Orabug: 36948578]
    {CVE-2024-42073}
    - net: wwan: iosm: Fix tainted pointer delete is case of region creation fail (Aleksandr Mishin)  [Orabug:
    36948578] {CVE-2024-40939}
    - net/mlx5: Always stop health timer during driver removal (Shay Drory)  [Orabug: 36948578]
    {CVE-2024-40906}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-20095.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-56766");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::developer_UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::developer_UEKR7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:5:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-modules-extra");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^(8|9)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8 / 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.15.0-305.176.4.el8uek', '5.15.0-305.176.4.el9uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2025-20095');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.15';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-305.176.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-305.176.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-305.176.4.el9uek', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'},
    {'reference':'bpftool-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'bpftool-5.15.0'},
    {'reference':'kernel-uek-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.15.0'},
    {'reference':'kernel-uek-container-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'},
    {'reference':'kernel-uek-core-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-core-5.15.0'},
    {'reference':'kernel-uek-debug-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.15.0'},
    {'reference':'kernel-uek-debug-core-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-core-5.15.0'},
    {'reference':'kernel-uek-debug-devel-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.15.0'},
    {'reference':'kernel-uek-debug-modules-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-5.15.0'},
    {'reference':'kernel-uek-debug-modules-extra-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-modules-extra-5.15.0'},
    {'reference':'kernel-uek-devel-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.15.0'},
    {'reference':'kernel-uek-doc-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.15.0'},
    {'reference':'kernel-uek-modules-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-5.15.0'},
    {'reference':'kernel-uek-modules-extra-5.15.0-305.176.4.el9uek', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-modules-extra-5.15.0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel-uek / kernel-uek-container / etc');
}
