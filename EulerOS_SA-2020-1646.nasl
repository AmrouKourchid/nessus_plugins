#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137488);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/06");

  script_cve_id(
    "CVE-2017-18207",
    "CVE-2018-1000802",
    "CVE-2019-9674",
    "CVE-2020-8492"
  );

  script_name(english:"EulerOS 2.0 SP2 : python (EulerOS-SA-2020-1646)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6
    through 3.6.10, 3.7 through 3.7.6, and 3.8 through
    3.8.1 allows an HTTP server to conduct Regular
    Expression Denial of Service (ReDoS) attacks against a
    client because of
    urllib.request.AbstractBasicAuthHandler catastrophic
    backtracking.(CVE-2020-8492)

  - Lib/zipfile.py in Python through 3.7.2 allows remote
    attackers to cause a denial of service (resource
    consumption) via a ZIP bomb.(CVE-2019-9674)

  - ** DISPUTED ** The Wave_read._read_fmt_chunk function
    in Lib/wave.py in Python through 3.6.4 does not ensure
    a nonzero channel value, which allows attackers to
    cause a denial of service (divide-by-zero and
    exception) via a crafted wav format audio file. NOTE:
    the vendor disputes this issue because Python
    applications 'need to be prepared to handle a wide
    variety of exceptions.'(CVE-2017-18207)

  - Python Software Foundation Python (CPython) version 2.7
    contains a CWE-77: Improper Neutralization of Special
    Elements used in a Command ('Command Injection')
    vulnerability in shutil module (make_archive function)
    that can result in Denial of service, Information gain
    via injection of arbitrary files on the system or
    entire drive. This attack appear to be exploitable via
    Passage of unfiltered user input to the function. This
    vulnerability appears to have been fixed in after
    commit
    add531a1e55b0a739b0f42582f1c9747e5649ace.(CVE-2018-1000
    802)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1646
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1771f22a");
  script_set_attribute(attribute:"solution", value:
"Update the affected python packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000802");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tkinter");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["python-2.7.5-58.h21",
        "python-devel-2.7.5-58.h21",
        "python-libs-2.7.5-58.h21",
        "tkinter-2.7.5-58.h21"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
