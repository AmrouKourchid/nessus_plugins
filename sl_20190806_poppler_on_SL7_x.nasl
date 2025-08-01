#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(128252);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/01");

  script_cve_id(
    "CVE-2018-16646",
    "CVE-2018-18897",
    "CVE-2018-19058",
    "CVE-2018-19059",
    "CVE-2018-19060",
    "CVE-2018-19149",
    "CVE-2018-20481",
    "CVE-2018-20650",
    "CVE-2018-20662",
    "CVE-2019-7310",
    "CVE-2019-9200",
    "CVE-2019-9631"
  );

  script_name(english:"Scientific Linux Security Update : poppler on SL7.x x86_64 (20190806)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - poppler: heap-based buffer over-read in XRef::getEntry
    in XRef.cc (CVE-2019-7310)

  - poppler: heap-based buffer overflow in function
    ImageStream::getLine() in Stream.cc (CVE-2019-9200)

  - poppler: infinite recursion in Parser::getObj function
    in Parser.cc (CVE-2018-16646)

  - poppler: memory leak in GfxColorSpace::setDisplayProfile
    in GfxState.cc (CVE-2018-18897)

  - poppler: reachable abort in Object.h (CVE-2018-19058)

  - poppler: out-of-bounds read in EmbFile::save2 in
    FileSpec.cc (CVE-2018-19059)

  - poppler: pdfdetach utility does not validate save paths
    (CVE-2018-19060)

  - poppler: NULL pointer dereference in
    _poppler_attachment_new (CVE-2018-19149)

  - poppler: NULL pointer dereference in the XRef::getEntry
    in XRef.cc (CVE-2018-20481)

  - poppler: reachable Object::dictLookup assertion in
    FileSpec class in FileSpec.cc (CVE-2018-20650)

  - poppler: SIGABRT PDFDoc::setup class in PDFDoc.cc
    (CVE-2018-20662)

  - poppler: heap-based buffer over-read in function
    downsample_row_box_filter in CairoRescaleBox.cc
    (CVE-2019-9631)");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=31117
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45e5b084");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9631");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evince-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:okular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:okular-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:okular-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:okular-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:okular-part");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:poppler-utils");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-3.28.2-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-browser-plugin-3.28.2-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-debuginfo-3.28.2-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-devel-3.28.2-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-dvi-3.28.2-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-libs-3.28.2-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"evince-nautilus-3.28.2-8.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"okular-4.10.5-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"okular-debuginfo-4.10.5-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"okular-devel-4.10.5-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"okular-libs-4.10.5-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"okular-part-4.10.5-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-cpp-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-cpp-devel-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-debuginfo-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-demos-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-devel-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-glib-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-glib-devel-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-qt-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-qt-devel-0.26.5-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"poppler-utils-0.26.5-38.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-browser-plugin / evince-debuginfo / evince-devel / etc");
}
