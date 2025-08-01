#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131882);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/04");

  script_cve_id(
    "CVE-2014-7923",
    "CVE-2014-7926",
    "CVE-2014-7940",
    "CVE-2014-9654",
    "CVE-2015-4844",
    "CVE-2016-6293",
    "CVE-2016-7415",
    "CVE-2017-15422",
    "CVE-2017-7867",
    "CVE-2017-7868"
  );
  script_bugtraq_id(72288, 72980);

  script_name(english:"EulerOS 2.0 SP2 : icu (EulerOS-SA-2019-2390)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the icu packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - Stack-based buffer overflow in the Locale class in
    common/locid.cpp in International Components for
    Unicode (ICU) through 57.1 for C/C++ allows remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    long locale string.(CVE-2016-7415)

  - Integer overflow in international date handling in
    International Components for Unicode (ICU) for C/C++
    before 60.1, as used in V8 in Google Chrome prior to
    63.0.3239.84 and other products, allowed a remote
    attacker to perform an out of bounds memory read via a
    crafted HTML page.(CVE-2017-15422)

  - The Regular Expressions package in International
    Components for Unicode (ICU) 52 before SVN revision
    292944, as used in Google Chrome before 40.0.2214.91,
    allows remote attackers to cause a denial of service
    (memory corruption) or possibly have unspecified other
    impact via vectors related to a look-behind
    expression.(CVE-2014-7923)

  - The Regular Expressions package in International
    Components for Unicode (ICU) 52 before SVN revision
    292944, as used in Google Chrome before 40.0.2214.91,
    allows remote attackers to cause a denial of service
    (memory corruption) or possibly have unspecified other
    impact via vectors related to a zero-length
    quantifier.(CVE-2014-7926)

  - The collator implementation in i18n/ucol.cpp in
    International Components for Unicode (ICU) 52 through
    SVN revision 293126, as used in Google Chrome before
    40.0.2214.91, does not initialize memory for a data
    structure, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via a crafted character sequence.(CVE-2014-7940)

  - The Regular Expressions package in International
    Components for Unicode (ICU) for C/C++ before
    2014-12-03, as used in Google Chrome before
    40.0.2214.91, calculates certain values without
    ensuring that they can be represented in a 24-bit
    field, which allows remote attackers to cause a denial
    of service (memory corruption) or possibly have
    unspecified other impact via a crafted string, a
    related issue to CVE-2014-7923.(CVE-2014-9654)

  - Unspecified vulnerability in Oracle Java SE 6u101,
    7u85, and 8u60, and Java SE Embedded 8u51, allows
    remote attackers to affect confidentiality, integrity,
    and availability via unknown vectors related to
    2D.(CVE-2015-4844)

  - The uloc_acceptLanguageFromHTTP function in
    common/uloc.cpp in International Components for Unicode
    (ICU) through 57.1 for C/C++ does not ensure that there
    is a '\0' character at the end of a certain temporary
    array, which allows remote attackers to cause a denial
    of service (out-of-bounds read) or possibly have
    unspecified other impact via a call with a long
    httpAcceptLanguage argument.(CVE-2016-6293)

  - International Components for Unicode (ICU) for C/C++
    before 2017-02-13 has an out-of-bounds write caused by
    a heap-based buffer overflow related to the
    utf8TextAccess function in common/utext.cpp and the
    utext_setNativeIndex* function.(CVE-2017-7867)

  - International Components for Unicode (ICU) for C/C++
    before 2017-02-13 has an out-of-bounds write caused by
    a heap-based buffer overflow related to the
    utf8TextAccess function in common/utext.cpp and the
    utext_moveIndex32* function.(CVE-2017-7868)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2390
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76e7c95c");
  script_set_attribute(attribute:"solution", value:
"Update the affected icu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4844");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-7415");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libicu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libicu-devel");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libicu-50.1.2-15.h4",
        "libicu-devel-50.1.2-15.h4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icu");
}
