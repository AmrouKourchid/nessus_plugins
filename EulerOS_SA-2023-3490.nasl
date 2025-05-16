#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188776);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2021-46174",
    "CVE-2022-47007",
    "CVE-2022-47008",
    "CVE-2022-47010",
    "CVE-2022-47011",
    "CVE-2022-47673",
    "CVE-2022-47695",
    "CVE-2022-47696",
    "CVE-2022-48063",
    "CVE-2022-48064",
    "CVE-2022-48065"
  );

  script_name(english:"EulerOS Virtualization 2.10.1 : binutils (EulerOS-SA-2023-3490)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the binutils package installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - Heap-based Buffer Overflow in function bfd_getl32 in Binutils objdump 3.37. (CVE-2021-46174)

  - An issue was discovered function stab_demangle_v3_arg in stabs.c in Binutils 2.34 thru 2.38, allows
    attackers to cause a denial of service due to memory leaks. (CVE-2022-47007)

  - An issue was discovered function make_tempdir, and make_tempname in bucomm.c in Binutils 2.34 thru 2.38,
    allows attackers to cause a denial of service due to memory leaks. (CVE-2022-47008)

  - An issue was discovered function pr_function_type in prdbg.c in Binutils 2.34 thru 2.38, allows attackers
    to cause a denial of service due to memory leaks. (CVE-2022-47010)

  - An issue was discovered function parse_stab_struct_fields in stabs.c in Binutils 2.34 thru 2.38, allows
    attackers to cause a denial of service due to memory leaks. (CVE-2022-47011)

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

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3490
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6029c30");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-47696");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.10.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.10.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.10.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "binutils-2.34-4.h22.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
