#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144019);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/02");

  script_cve_id("CVE-2019-14869");

  script_name(english:"Virtuozzo 7 : ghostscript / ghostscript-cups / ghostscript-doc / etc (VZLSA-2019-3888)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for ghostscript is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Ghostscript suite contains utilities for rendering PostScript and
PDF documents. Ghostscript translates PostScript code to common bitmap
formats so that the code can be displayed or printed.

Security Fix(es) :

* ghostscript: -dSAFER escape in .charkeys (701841) (CVE-2019-14869)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2019-3888.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?152c6ab1");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3888");
  script_set_attribute(attribute:"solution", value:
"Update the affected ghostscript / ghostscript-cups / ghostscript-doc / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14869");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libgs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["ghostscript-9.25-2.vl7.3",
        "ghostscript-cups-9.25-2.vl7.3",
        "ghostscript-doc-9.25-2.vl7.3",
        "ghostscript-gtk-9.25-2.vl7.3",
        "libgs-9.25-2.vl7.3",
        "libgs-devel-9.25-2.vl7.3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-cups / ghostscript-doc / etc");
}
