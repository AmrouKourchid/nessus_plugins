#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(128266);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/01");

  script_cve_id(
    "CVE-2018-1304",
    "CVE-2018-1305",
    "CVE-2018-8014",
    "CVE-2018-8034"
  );

  script_name(english:"Scientific Linux Security Update : tomcat on SL7.x x86_64 (20190806)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - tomcat: Incorrect handling of empty string URL in
    security constraints can lead to unintended exposure of
    resources (CVE-2018-1304)

  - tomcat: Late application of security constraints can
    lead to resource exposure for unauthorised users
    (CVE-2018-1305)

  - tomcat: Insecure defaults in CORS filter enable
    'supportsCredentials' for all origins (CVE-2018-8014)

  - tomcat: Host name verification missing in WebSocket
    client (CVE-2018-8034)");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=24724
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2aa9ccdd");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tomcat-webapps");
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
if (rpm_check(release:"SL7", reference:"tomcat-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-admin-webapps-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-admin-webapps-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-docs-webapp-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-docs-webapp-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-el-2.2-api-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-el-2.2-api-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-javadoc-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-javadoc-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-jsp-2.2-api-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-jsp-2.2-api-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-jsvc-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-jsvc-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-lib-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-lib-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-servlet-3.0-api-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-servlet-3.0-api-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-webapps-7.0.76-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tomcat-webapps-7.0.76-9.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
