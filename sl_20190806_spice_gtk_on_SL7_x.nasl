#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('compat.inc');

if (description)
{
  script_id(128263);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/01");

  script_cve_id("CVE-2018-10893");

  script_name(english:"Scientific Linux Security Update : spice-gtk on SL7.x x86_64 (20190806)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"The libgovirt packages contain a library that allows applications to
use the oVirt Representational State Transfer (REST) API to list
virtual machines (VMs) managed by an oVirt instance. The library is
also used to get the connection parameters needed to establish a
connection to the VMs using Simple Protocol For Independent Computing
Environments (SPICE) or Virtual Network Computing (VNC).

The spice-vdagent packages provide a SPICE agent for Linux guests.

The virt-viewer packages provide Virtual Machine Viewer, which is a
lightweight interface for interacting with the graphical display of a
virtualized guest.

Security Fix(es) :

  - spice-client: Insufficient encoding checks for LZ can
    cause different integer/buffer overflows
    (CVE-2018-10893)");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=23346
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f12cd48");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10893");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgovirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgovirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-gtk3-vala");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-vdagent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:spice-vdagent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:virt-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:virt-viewer-debuginfo");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgovirt-0.3.4-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgovirt-debuginfo-0.3.4-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgovirt-devel-0.3.4-3.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-glib-0.35-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-glib-devel-0.35-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-gtk-debuginfo-0.35-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-gtk-tools-0.35-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-gtk3-0.35-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-gtk3-devel-0.35-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-gtk3-vala-0.35-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-vdagent-0.14.0-18.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"spice-vdagent-debuginfo-0.14.0-18.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"virt-viewer-5.0-15.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"virt-viewer-debuginfo-5.0-15.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgovirt / libgovirt-debuginfo / libgovirt-devel / spice-glib / etc");
}
