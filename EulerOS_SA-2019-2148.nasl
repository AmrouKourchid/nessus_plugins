#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130857);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/12");

  script_cve_id(
    "CVE-2014-9745",
    "CVE-2014-9747",
    "CVE-2015-9290",
    "CVE-2015-9381",
    "CVE-2015-9382",
    "CVE-2015-9383"
  );

  script_name(english:"EulerOS 2.0 SP5 : freetype (EulerOS-SA-2019-2148)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the freetype packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The t42_parse_encoding function in type42/t42parse.c in
    FreeType before 2.5.4 does not properly update the
    current position for immediates-only mode, which allows
    remote attackers to cause a denial of service (infinite
    loop) via a Type42 font.(CVE-2014-9747)

  - The parse_encoding function in type1/t1load.c in
    FreeType before 2.5.3 allows remote attackers to cause
    a denial of service (infinite loop) via a 'broken
    number-with-base' in a Postscript stream, as
    demonstrated by 8#garbage.(CVE-2014-9745)

  - In FreeType before 2.6.1, a buffer over-read occurs in
    type1/t1parse.c on function T1_Get_Private_Dict where
    there is no check that the new values of cur and limit
    are sensible before going to Again.(CVE-2015-9290)

  - FreeType before 2.6.1 has a heap-based buffer over-read
    in T1_Get_Private_Dict in
    type1/t1parse.c.(CVE-2015-9381)

  - FreeType before 2.6.1 has a buffer over-read in
    skip_comment in psaux/psobjs.c because
    ps_parser_skip_PS_token is mishandled in an
    FT_New_Memory_Face operation.(CVE-2015-9382)

  - FreeType before 2.6.2 has a heap-based buffer over-read
    in tt_cmap14_validate in sfnt/ttcmap.c.(CVE-2015-9383)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2148
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea9acb90");
  script_set_attribute(attribute:"solution", value:
"Update the affected freetype packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-9290");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["freetype-2.4.11-15.h9.eulerosv2r7",
        "freetype-devel-2.4.11-15.h9.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype");
}
