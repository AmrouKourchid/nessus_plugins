#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3695-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181753);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id(
    "CVE-2020-19726",
    "CVE-2021-32256",
    "CVE-2022-4285",
    "CVE-2022-35205",
    "CVE-2022-35206",
    "CVE-2022-44840",
    "CVE-2022-45703",
    "CVE-2022-47673",
    "CVE-2022-47695",
    "CVE-2022-47696",
    "CVE-2022-48063",
    "CVE-2022-48064",
    "CVE-2022-48065",
    "CVE-2023-0687",
    "CVE-2023-1579",
    "CVE-2023-1972",
    "CVE-2023-2222",
    "CVE-2023-25585",
    "CVE-2023-25587",
    "CVE-2023-25588"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3695-1");

  script_name(english:"SUSE SLES12 Security Update : binutils (SUSE-SU-2023:3695-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:3695-1 advisory.

  - An issue was discovered in binutils libbfd.c 2.36 relating to the auxiliary symbol data allows attackers
    to read or write to system memory or cause a denial of service. (CVE-2020-19726)

  - An issue was discovered in GNU libiberty, as distributed in GNU Binutils 2.36. It is a stack-overflow
    issue in demangle_type in rust-demangle.c. (CVE-2021-32256)

  - An issue was discovered in Binutils readelf 2.38.50, reachable assertion failure in function
    display_debug_names allows attackers to cause a denial of service. (CVE-2022-35205)

  - Null pointer dereference vulnerability in Binutils readelf 2.38.50 via function
    read_and_display_attr_value in file dwarf.c. (CVE-2022-35206)

  - An illegal memory access flaw was found in the binutils package. Parsing an ELF file containing corrupt
    symbol version information may result in a denial of service. This issue is the result of an incomplete
    fix for CVE-2020-16599. (CVE-2022-4285)

  - Heap buffer overflow vulnerability in binutils readelf before 2.40 via function find_section_in_set in
    file readelf.c. (CVE-2022-44840)

  - Heap buffer overflow vulnerability in binutils readelf before 2.40 via function display_debug_section in
    file readelf.c. (CVE-2022-45703)

  - An issue was discovered in Binutils addr2line before 2.39.3, function parse_module contains multiple out
    of bound reads which may cause a denial of service or other unspecified impacts. (CVE-2022-47673)

  - An issue was discovered Binutils objdump before 2.39.3 allows attackers to cause a denial of service or
    other unspecified impacts via function bfd_mach_o_get_synthetic_symtab in match-o.c. (CVE-2022-47695)

  - An issue was discovered Binutils objdump before 2.39.3 allows attackers to cause a denial of service or
    other unspecified impacts via function compare_symbols. (CVE-2022-47696)

  - GNU Binutils before 2.40 was discovered to contain an excessive memory consumption vulnerability via the
    function load_separate_debug_files at dwarf2.c. The attacker could supply a crafted ELF file and cause a
    DNS attack. (CVE-2022-48063)

  - GNU Binutils before 2.40 was discovered to contain an excessive memory consumption vulnerability via the
    function bfd_dwarf2_find_nearest_line_with_alt at dwarf2.c. The attacker could supply a crafted ELF file
    and cause a DNS attack. (CVE-2022-48064)

  - GNU Binutils before 2.40 was discovered to contain a memory leak vulnerability var the function
    find_abstract_instance in dwarf2.c. (CVE-2022-48065)

  - ** DISPUTED ** A vulnerability was found in GNU C Library 2.38. It has been declared as critical. This
    vulnerability affects the function __monstartup of the file gmon.c of the component Call Graph Monitor.
    The manipulation leads to buffer overflow. It is recommended to apply a patch to fix this issue.
    VDB-220246 is the identifier assigned to this vulnerability. NOTE: The real existence of this
    vulnerability is still doubted at the moment. The inputs that induce this vulnerability are basically
    addresses of the running application that is built with gmon enabled. It's basically trusted input or
    input that needs an actual security flaw to be compromised or controlled. (CVE-2023-0687)

  - Heap based buffer overflow in binutils-gdb/bfd/libbfd.c in bfd_getl64. (CVE-2023-1579)

  - A potential heap based buffer overflow was found in _bfd_elf_slurp_version_tables() in bfd/elf.c. This may
    lead to loss of availability. (CVE-2023-1972)

  - A flaw was found in Binutils. The use of an uninitialized field in the struct module *module may lead to
    application crash and local denial of service. (CVE-2023-25585)

  - A flaw was found in Binutils. The field `the_bfd` of `asymbol`struct is uninitialized in the
    `bfd_mach_o_get_synthetic_symtab` function, which may lead to an application crash and local denial of
    service. (CVE-2023-25588)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214625");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-September/016227.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62755f3f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-19726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32256");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-35205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-35206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-44840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-47673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-47695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-47696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25588");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0687");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf-nobfd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
    {'reference':'binutils-2.41-9.53.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'binutils-devel-2.41-9.53.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'binutils-gold-2.41-9.53.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libctf-nobfd0-2.41-9.53.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libctf0-2.41-9.53.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'binutils-devel-2.41-9.53.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'binutils-gold-2.41-9.53.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'binutils-2.41-9.53.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libctf-nobfd0-2.41-9.53.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libctf0-2.41-9.53.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-devel / binutils-gold / libctf-nobfd0 / libctf0');
}
