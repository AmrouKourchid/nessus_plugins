#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(131055);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/11");

  script_cve_id("CVE-2019-0155");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20191114)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Security Fix(es) :

  - hw: Intel GPU blitter manipulation can allow for
    arbitrary kernel memory write (CVE-2019-0155)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1911&L=SCIENTIFIC-LINUX-ERRATA&P=2301
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1282f860");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0155");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-754.24.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-754.24.3.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
