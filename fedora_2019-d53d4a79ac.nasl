#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-d53d4a79ac.
#

include('compat.inc');

if (description)
{
  script_id(131105);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/11");

  script_cve_id(
    "CVE-2018-14054",
    "CVE-2018-14325",
    "CVE-2018-14326",
    "CVE-2018-14379",
    "CVE-2018-14403",
    "CVE-2018-14446"
  );
  script_xref(name:"FEDORA", value:"2019-d53d4a79ac");

  script_name(english:"Fedora 31 : libmp4v2 (2019-d53d4a79ac)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Fix crash made by the new patches 

----

Fix https://nvd.nist.gov/vuln/detail/CVE-2018-14446
https://nvd.nist.gov/vuln/detail/CVE-2018-14403
https://nvd.nist.gov/vuln/detail/CVE-2018-14379
https://nvd.nist.gov/vuln/detail/CVE-2018-14326
https://nvd.nist.gov/vuln/detail/CVE-2018-14325
https://nvd.nist.gov/vuln/detail/CVE-2018-14054 based on
https://github.com/TechSmith/mp4v2/pull/27 and
https://github.com/sergiomb2/libmp4v2/

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-d53d4a79ac");
  script_set_attribute(attribute:"see_also", value:"https://github.com/sergiomb2/libmp4v2/");
  script_set_attribute(attribute:"solution", value:
"Update the affected libmp4v2 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14403");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libmp4v2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"libmp4v2-2.1.0-0.19.trunkREV507.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmp4v2");
}
