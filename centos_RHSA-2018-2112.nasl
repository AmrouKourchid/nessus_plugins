#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2112 and 
# CentOS Errata and Security Advisory 2018:2112 respectively.
#

include('compat.inc');

if (description)
{
  script_id(111074);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/04");

  script_cve_id(
    "CVE-2017-7762",
    "CVE-2018-12359",
    "CVE-2018-12360",
    "CVE-2018-12362",
    "CVE-2018-12363",
    "CVE-2018-12364",
    "CVE-2018-12365",
    "CVE-2018-12366",
    "CVE-2018-5156",
    "CVE-2018-5188",
    "CVE-2018-6126"
  );
  script_xref(name:"RHSA", value:"2018:2112");

  script_name(english:"CentOS 6 : firefox (CESA-2018:2112)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for firefox is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Firefox is an open source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 60.1.0 ESR.

Security Fix(es) :

* Mozilla: Memory safety bugs fixed in Firefox 61, Firefox ESR 60.1,
and Firefox ESR 52.9 (CVE-2018-5188)

* Mozilla: Buffer overflow using computed size of canvas element
(CVE-2018-12359)

* Mozilla: Use-after-free using focus() (CVE-2018-12360)

* Mozilla: Media recorder segmentation fault when track type is
changed during capture (CVE-2018-5156)

* Skia: Heap buffer overflow rasterizing paths in SVG (CVE-2018-6126)

* Mozilla: Integer overflow in SSSE3 scaler (CVE-2018-12362)

* Mozilla: Use-after-free when appending DOM nodes (CVE-2018-12363)

* Mozilla: CSRF attacks through 307 redirects and NPAPI plugins
(CVE-2018-12364)

* Mozilla: address bar username and password spoofing in reader mode
(CVE-2017-7762)

* Mozilla: Compromised IPC child process can list local filenames
(CVE-2018-12365)

* Mozilla: Invalid data handling during QCMS transformations
(CVE-2018-12366)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Alex Gaynor, Christoph Diehl, Christian
Holler, Jason Kratzer, David Major, Jon Coppeard, Nicolas B. Pierron,
Marcia Knous, Ronald Crane, Nils, F. Alonso (revskills), David Black,
and OSS-Fuzz as the original reporters.");
  # https://lists.centos.org/pipermail/centos-announce/2018-July/022962.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7cfc2e5");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5188");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"firefox-60.1.0-5.el6.centos", allowmaj:TRUE)) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
