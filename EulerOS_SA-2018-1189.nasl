#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110853);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id(
    "CVE-2018-5146",
    "CVE-2018-5148",
    "CVE-2018-5150",
    "CVE-2018-5154",
    "CVE-2018-5155",
    "CVE-2018-5157",
    "CVE-2018-5158",
    "CVE-2018-5159",
    "CVE-2018-5168",
    "CVE-2018-5178",
    "CVE-2018-5183"
  );

  script_name(english:"EulerOS 2.0 SP3 : firefox (EulerOS-SA-2018-1189)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the firefox package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An out of bounds write flaw was found in the processing
    of vorbis audio data. A maliciously crafted file or
    audio stream could cause the application to crash or,
    potentially, execute arbitrary code.(CVE-2018-5146)

  - Use-after-free in compositor potentially allows code
    execution (CVE-2018-5148)

  - Memory safety bugs fixed in Firefox 60 and Firefox ESR
    52.8 (CVE-2018-5150)

  - Backport critical security fixes in Skia
    (CVE-2018-5183)

  - Use-after-free with SVG animations and clip paths
    (CVE-2018-5154)

  - Use-after-free with SVG animations and text paths
    (CVE-2018-5155)

  - Same-origin bypass of PDF Viewer to view protected PDF
    files (CVE-2018-5157)

  - Malicious PDF can inject JavaScript into PDF Viewer
    (CVE-2018-5158)

  - Integer overflow and out-of-bounds write in Skia
    (CVE-2018-5159)

  - Lightweight themes can be installed without user
    interaction (CVE-2018-5168)

  - Buffer overflow during UTF-8 to Unicode string
    conversion through legacy extension (CVE-2018-5178)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1189
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c98c21af");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["firefox-52.8.0-1.h1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg, allowmaj:TRUE)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
