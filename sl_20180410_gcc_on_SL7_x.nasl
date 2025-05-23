#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(109446);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/16");

  script_cve_id("CVE-2017-11671");

  script_name(english:"Scientific Linux Security Update : gcc on SL7.x x86_64 (20180410)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - gcc: GCC generates incorrect code for RDRAND/RDSEED
    intrinsics (CVE-2017-11671)

Additional Changes :");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1804&L=scientific-linux-errata&F=&S=&P=7875
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87feb72a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgnat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgnat-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libmudflap-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libtsan-static");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"cpp-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-base-debuginfo-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-c++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-debuginfo-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-gfortran-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-gnat-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-go-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-objc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-objc++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"gcc-plugin-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libasan-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libasan-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libatomic-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libatomic-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgcc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgfortran-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgfortran-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgnat-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgnat-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgnat-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgo-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgo-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgo-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgomp-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libitm-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libitm-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libitm-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libmudflap-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libmudflap-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libmudflap-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libobjc-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libquadmath-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libquadmath-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libquadmath-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libstdc++-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libstdc++-devel-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libstdc++-docs-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libstdc++-static-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtsan-4.8.5-28.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libtsan-static-4.8.5-28.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-base-debuginfo / gcc-c++ / gcc-debuginfo / etc");
}
