#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-578fa05659.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120441);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/05");

  script_cve_id(
    "CVE-2017-5852",
    "CVE-2017-5853",
    "CVE-2017-5854",
    "CVE-2017-5855",
    "CVE-2017-5886",
    "CVE-2017-6840",
    "CVE-2017-6842",
    "CVE-2017-6843",
    "CVE-2017-6844",
    "CVE-2017-6845",
    "CVE-2017-6847",
    "CVE-2017-6848",
    "CVE-2017-7378",
    "CVE-2017-7379",
    "CVE-2017-7380",
    "CVE-2017-7381",
    "CVE-2017-7382",
    "CVE-2017-7383",
    "CVE-2017-7994",
    "CVE-2017-8054",
    "CVE-2017-8378",
    "CVE-2017-8787",
    "CVE-2018-5295",
    "CVE-2018-5308",
    "CVE-2018-8000"
  );
  script_xref(name:"FEDORA", value:"2018-578fa05659");

  script_name(english:"Fedora 28 : mingw-podofo (2018-578fa05659)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Backport security fixes for: CVE-2017-7380, CVE-2017-7381,
CVE-2017-7382, CVE-2017-7383, CVE-2017-5852, CVE-2017-5853,
CVE-2017-6844, CVE-2017-5854, CVE-2017-5855, CVE-2017-5886,
CVE-2018-8000, CVE-2017-6840, CVE-2017-6842, CVE-2017-6843,
CVE-2017-6845, CVE-2017-6847, CVE-2017-6848, CVE-2017-7378,
CVE-2017-7379, CVE-2017-7994, CVE-2017-8054, CVE-2017-8378,
CVE-2017-8787, CVE-2018-5295, CVE-2018-5308

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-578fa05659");
  script_set_attribute(attribute:"solution", value:
"Update the affected mingw-podofo package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8378");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-podofo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"mingw-podofo-0.9.5-6.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mingw-podofo");
}
