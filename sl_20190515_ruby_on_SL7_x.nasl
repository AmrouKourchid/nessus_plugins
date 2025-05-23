#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(125208);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/22");

  script_cve_id(
    "CVE-2019-8322",
    "CVE-2019-8323",
    "CVE-2019-8324",
    "CVE-2019-8325"
  );

  script_name(english:"Scientific Linux Security Update : ruby on SL7.x x86_64 (20190515)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - rubygems: Installing a malicious gem may lead to
    arbitrary code execution (CVE-2019-8324)

  - rubygems: Escape sequence injection vulnerability in gem
    owner (CVE-2019-8322)

  - rubygems: Escape sequence injection vulnerability in API
    response handling (CVE-2019-8323)

  - rubygems: Escape sequence injection vulnerability in
    errors (CVE-2019-8325)");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1905&L=SCIENTIFIC-LINUX-ERRATA&P=4867
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73809b35");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8324");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rubygems-devel");
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


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-debuginfo-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-devel-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"ruby-doc-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"ruby-irb-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-libs-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-tcltk-2.0.0.648-35.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-bigdecimal-1.2.0-35.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-io-console-0.4.2-35.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-json-1.7.7-35.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-minitest-4.3.2-35.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-psych-2.0.0-35.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-rake-0.9.6-35.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-rdoc-4.0.0-35.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"rubygems-2.0.14.1-35.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"rubygems-devel-2.0.14.1-35.el7_6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-doc / ruby-irb / etc");
}
