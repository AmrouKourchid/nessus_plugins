#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(126145);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2019-10160", "CVE-2019-9636");

  script_name(english:"Scientific Linux Security Update : python on SL7.x x86_64 (20190620)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - python: regression of CVE-2019-9636 due to functional
    fix to allow port numbers in netloc (CVE-2019-10160)");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1906&L=SCIENTIFIC-LINUX-ERRATA&P=9350
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99e5b4cf");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9636");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-2.7.5-80.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-debug-2.7.5-80.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-debuginfo-2.7.5-80.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-devel-2.7.5-80.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-libs-2.7.5-80.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-test-2.7.5-80.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-tools-2.7.5-80.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tkinter-2.7.5-80.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-debuginfo / python-devel / etc");
}
