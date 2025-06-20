#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(128260);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/01");

  script_cve_id(
    "CVE-2017-17742",
    "CVE-2018-1000073",
    "CVE-2018-1000074",
    "CVE-2018-1000075",
    "CVE-2018-1000076",
    "CVE-2018-1000077",
    "CVE-2018-1000078",
    "CVE-2018-1000079",
    "CVE-2018-16396",
    "CVE-2018-6914",
    "CVE-2018-8777",
    "CVE-2018-8778",
    "CVE-2018-8779",
    "CVE-2018-8780"
  );

  script_name(english:"Scientific Linux Security Update : ruby on SL7.x x86_64 (20190806)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - ruby: HTTP response splitting in WEBrick
    (CVE-2017-17742)

  - ruby: DoS by large request in WEBrick (CVE-2018-8777)

  - ruby: Buffer under-read in String#unpack (CVE-2018-8778)

  - ruby: Unintentional directory traversal by poisoned NULL
    byte in Dir (CVE-2018-8780)

  - ruby: Tainted flags are not propagated in Array#pack and
    String#unpack with some directives (CVE-2018-16396)

  - rubygems: Path traversal when writing to a symlinked
    basedir outside of the root (CVE-2018-1000073)

  - rubygems: Unsafe Object Deserialization Vulnerability in
    gem owner allowing arbitrary code execution on specially
    crafted YAML (CVE-2018-1000074)

  - rubygems: Improper verification of signatures in tarball
    allows to install mis-signed gem (CVE-2018-1000076)

  - rubygems: Missing URL validation on spec home attribute
    allows malicious gem to set an invalid homepage URL
    (CVE-2018-1000077)

  - rubygems: XSS vulnerability in homepage attribute when
    displayed via gem server (CVE-2018-1000078)

  - rubygems: Path traversal issue during gem installation
    allows to write to arbitrary filesystem locations
    (CVE-2018-1000079)

  - ruby: Unintentional file and directory creation with
    directory traversal in tempfile and tmpdir
    (CVE-2018-6914)

  - ruby: Unintentional socket creation by poisoned NULL
    byte in UNIXServer and UNIXSocket (CVE-2018-8779)

  - rubygems: Infinite loop vulnerability due to negative
    size in tar header causes Denial of Service
    (CVE-2018-1000075)");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=18537
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64ba4fae");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8780");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1000076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-debuginfo-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-devel-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ruby-doc-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-doc-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", reference:"ruby-irb-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-irb-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-libs-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ruby-tcltk-2.0.0.648-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-bigdecimal-1.2.0-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-io-console-0.4.2-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-json-1.7.7-36.el7")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-minitest-4.3.2-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-minitest-4.3.2-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-psych-2.0.0-36.el7")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-rake-0.9.6-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-rake-0.9.6-36.el7")) flag++;
if (rpm_check(release:"SL7", reference:"rubygem-rdoc-4.0.0-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygem-rdoc-4.0.0-36.el7")) flag++;
if (rpm_check(release:"SL7", reference:"rubygems-2.0.14.1-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygems-2.0.14.1-36.el7")) flag++;
if (rpm_check(release:"SL7", reference:"rubygems-devel-2.0.14.1-36.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rubygems-devel-2.0.14.1-36.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-doc / ruby-irb / etc");
}
