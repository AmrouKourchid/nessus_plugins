#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151304);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/11");

  script_cve_id(
    "CVE-2014-10401",
    "CVE-2014-10402",
    "CVE-2019-20919",
    "CVE-2020-14392",
    "CVE-2020-14393"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : perl-DBI (EulerOS-SA-2021-2112)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the perl-DBI package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An issue was discovered in the DBI module before 1.643
    for Perl. The hv_fetch() documentation requires
    checking for NULL and the code does that. But, shortly
    thereafter, it calls SvOK(profile), causing a NULL
    pointer dereference.(CVE-2019-20919)

  - An issue was discovered in the DBI module before 1.632
    for Perl. DBD::File drivers can open files from folders
    other than those specifically passed via the f_dir
    attribute.(CVE-2014-10401)

  - A buffer overflow was found in perl-DBI before version
    1.643 in DBI.xs. This flaw allows a local attacker who
    can supply a string longer than 300 characters to cause
    an out-of-bounds write. The highest threat from this
    vulnerability is to integrity and system
    availability.(CVE-2020-14393)

  - An untrusted pointer dereference flaw was found in
    Perl-DBI before version 1.643. This flaw allows a local
    attacker who can manipulate calls to dbd_db_login6_sv()
    to cause memory corruption. The highest threat from
    this vulnerability is to system
    availability.(CVE-2020-14392)

  - An issue was discovered in the DBI module through 1.643
    for Perl. DBD::File drivers can open files from folders
    other than those specifically passed via the f_dir
    attribute in the data source name (DSN). NOTE: this
    issue exists because of an incomplete fix for
    CVE-2014-10401.(CVE-2014-10402)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2112
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8382d315");
  script_set_attribute(attribute:"solution", value:
"Update the affected perl-DBI packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14393");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-DBI");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["perl-DBI-1.627-4.h4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-DBI");
}
