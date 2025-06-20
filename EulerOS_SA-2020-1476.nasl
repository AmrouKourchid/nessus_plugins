#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135638);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2013-7422", "CVE-2016-1238", "CVE-2016-6185");
  script_bugtraq_id(75704);

  script_name(english:"EulerOS Virtualization 3.0.2.2 : perl (EulerOS-SA-2020-1476)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the perl packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - Integer underflow in regcomp.c in Perl before 5.20, as
    used in Apple OS X before 10.10.5 and other products,
    allows context-dependent attackers to execute arbitrary
    code or cause a denial of service (application crash)
    via a long digit string associated with an invalid
    backreference within a regular
    expression.(CVE-2013-7422)

  - 1) cpan/Archive-Tar/bin/ptar, (2)
    cpan/Archive-Tar/bin/ptardiff, (3)
    cpan/Archive-Tar/bin/ptargrep, (4)
    cpan/CPAN/scripts/cpan, (5) cpan/Digest-SHA/shasum, (6)
    cpan/Encode/bin/enc2xs, (7) cpan/Encode/bin/encguess,
    (8) cpan/Encode/bin/piconv, (9)
    cpan/Encode/bin/ucmlint, (10) cpan/Encode/bin/unidump,
    (11) cpan/ExtUtils-MakeMaker/bin/instmodsh, (12)
    cpan/IO-Compress/bin/zipdetails, (13)
    cpan/JSON-PP/bin/json_pp, (14)
    cpan/Test-Harness/bin/prove, (15)
    dist/ExtUtils-ParseXS/lib/ExtUtils/xsubpp, (16)
    dist/Module-CoreList/corelist, (17)
    ext/Pod-Html/bin/pod2html, (18) utils/c2ph.PL, (19)
    utils/h2ph.PL, (20) utils/h2xs.PL, (21)
    utils/libnetcfg.PL, (22) utils/perlbug.PL, (23)
    utils/perldoc.PL, (24) utils/perlivp.PL, and (25)
    utils/splain.PL in Perl 5.x before 5.22.3-RC2 and 5.24
    before 5.24.1-RC2 do not properly remove . (period)
    characters from the end of the includes directory
    array, which might allow local users to gain privileges
    via a Trojan horse module under the current working
    directory.(CVE-2016-1238)

  - The XSLoader::load method in XSLoader in Perl does not
    properly locate .so files when called in a string eval,
    which might allow local users to execute arbitrary code
    via a Trojan horse library under the current working
    directory.(CVE-2016-6185)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1476
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33069519");
  script_set_attribute(attribute:"solution", value:
"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-7422");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-6185");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-macros");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["perl-5.16.3-292.h11.eulerosv2r7",
        "perl-Pod-Escapes-1.04-292.h11.eulerosv2r7",
        "perl-libs-5.16.3-292.h11.eulerosv2r7",
        "perl-macros-5.16.3-292.h11.eulerosv2r7"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
