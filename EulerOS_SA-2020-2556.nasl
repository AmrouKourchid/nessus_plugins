#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144219);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/02");

  script_cve_id(
    "CVE-2018-8881",
    "CVE-2018-8882",
    "CVE-2018-10016",
    "CVE-2018-10316",
    "CVE-2018-19214",
    "CVE-2018-19215",
    "CVE-2018-19755",
    "CVE-2018-1000667"
  );

  script_name(english:"EulerOS 2.0 SP5 : nasm (EulerOS-SA-2020-2556)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nasm package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - NASM nasm-2.13.03 nasm- 2.14rc15 version 2.14rc15 and
    earlier contains a memory corruption (crashed) of nasm
    when handling a crafted file due to function
    assemble_file(inname, depend_ptr) at asm/nasm.c:482.
    vulnerability in function assemble_file(inname,
    depend_ptr) at asm/nasm.c:482. that can result in
    aborting/crash nasm program. This attack appear to be
    exploitable via a specially crafted asm
    file..(CVE-2018-1000667)

  - Netwide Assembler (NASM) 2.14rc0 has a division-by-zero
    vulnerability in the expr5 function in asm/eval.c via a
    malformed input file.(CVE-2018-10016)

  - Netwide Assembler (NASM) 2.14rc0 has an endless while
    loop in the assemble_file function of asm/nasm.c
    because of a globallineno integer
    overflow.(CVE-2018-10316)

  - Netwide Assembler (NASM) 2.14rc15 has a heap-based
    buffer over-read in expand_mmac_params in asm/preproc.c
    for insufficient input.(CVE-2018-19214)

  - Netwide Assembler (NASM) 2.14rc16 has a heap-based
    buffer over-read in expand_mmac_params in asm/preproc.c
    for the special cases of the % and $ and !
    characters.(CVE-2018-19215)

  - There is an illegal address access at asm/preproc.c
    (function: is_mmacro) in Netwide Assembler (NASM)
    2.14rc16 that will cause a denial of service
    (out-of-bounds array access) because a certain
    conversion can result in a negative
    integer.(CVE-2018-19755)

  - Netwide Assembler (NASM) 2.13.02rc2 has a heap-based
    buffer over-read in the function tokenize in
    asm/preproc.c, related to an unterminated
    string.(CVE-2018-8881)

  - Netwide Assembler (NASM) 2.13.02rc2 has a stack-based
    buffer under-read in the function ieee_shr in
    asm/float.c via a large shift value.(CVE-2018-8882)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2556
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fff1ed82");
  script_set_attribute(attribute:"solution", value:
"Update the affected nasm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8881");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8882");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nasm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["nasm-2.10.07-7.h4.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nasm");
}
