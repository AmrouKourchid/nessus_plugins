#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-6a8028084d.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120497);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/05");

  script_cve_id("CVE-2018-5773");
  script_xref(name:"FEDORA", value:"2018-6a8028084d");

  script_name(english:"Fedora 29 : python-markdown2 (2018-6a8028084d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"#### python-markdown2 2.3.6 ####

  - [pull #282] Add TOC depth option

  - [pull #283] Fix to add TOC html to output via CLI

  - [pull #284] Do not remove anchors in safe_mode

  - [pull #288] fixing cuddled-lists with a single list item

  - [pull #292] Fix Wrong rendering of last list element

  - [pull #295] link-patterns fix

  - [pull #300] Replace a deprecated method

  - [pull #301] DeprecationWarning: invalid escape sequence

  - [pull #302] Fix 'make test' in Python 3

  - [pull #303] Fix CVE-2018-5773

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-6a8028084d");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-markdown2 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5773");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-markdown2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"python-markdown2-2.3.6-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-markdown2");
}
