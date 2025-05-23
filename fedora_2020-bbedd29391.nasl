#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-bbedd29391.
#

include('compat.inc');

if (description)
{
  script_id(137735);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/06");

  script_cve_id(
    "CVE-2020-4046",
    "CVE-2020-4047",
    "CVE-2020-4048",
    "CVE-2020-4049",
    "CVE-2020-4050"
  );
  script_xref(name:"FEDORA", value:"2020-bbedd29391");
  script_xref(name:"IAVA", value:"2020-A-0266-S");

  script_name(english:"Fedora 31 : wordpress (2020-bbedd29391)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"**WordPress 5.4.2 Security and Maintenance Release**

This security and maintenance release features 23 fixes and
enhancements. Plus, it adds a number of security fixes&mdash;see the
list below.

These bugs affect WordPress versions 5.4.1 and earlier; version 5.4.2
fixes them, so you&rsquo;ll want to upgrade.

**Security Updates**

WordPress versions 5.4 and earlier are affected by the following bugs,
which are fixed in version 5.4.2. If you haven&rsquo;t yet updated to
5.4, there are also updated versions of 5.3 and earlier that fix the
security issues.

  - Props to Sam Thomas (jazzy2fives) for finding an XSS
    issue where authenticated users with low privileges are
    able to add JavaScript to posts in the block editor.

  - Props to Luigi &ndash; (gubello.me) for discovering an
    XSS issue where authenticated users with upload
    permissions are able to add JavaScript to media files.

  - Props to Ben Bidner of the WordPress Security Team for
    finding an open redirect issue in
    wp_validate_redirect().

  - Props to Nrimo Ing Pandum for finding an authenticated
    XSS issue via theme uploads.

  - Props to Simon Scannell of RIPS Technologies for finding
    an issue where set-screen-option can be misused by
    plugins leading to privilege escalation.

  - Props to Carolina Nymark for discovering an issue where
    comments from password-protected posts and pages could
    be displayed under certain conditions.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-bbedd29391");
  script_set_attribute(attribute:"solution", value:
"Update the affected wordpress package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4050");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-4047");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"wordpress-5.4.2-1.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
