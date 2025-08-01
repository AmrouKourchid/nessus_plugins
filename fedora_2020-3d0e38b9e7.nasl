#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-3d0e38b9e7.
#

include('compat.inc');

if (description)
{
  script_id(143356);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/07");

  script_cve_id("CVE-2020-25654");
  script_xref(name:"FEDORA", value:"2020-3d0e38b9e7");

  script_name(english:"Fedora 33 : pacemaker (2020-3d0e38b9e7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"** Wed Nov 18 2020 Klaus Wenninger <kwenning@redhat.com> -
2.0.5-0.7.rc3 **

  - a little more syncing with upstream spec-file

** Tue Nov 17 2020 Klaus Wenninger <kwenning@redhat.com> -
2.0.5-0.6.rc3 **

  - Update for new upstream tarball for release candidate:
    Pacemaker-2.0.5-rc3 for full details, see included
    ChangeLog file or
    https://github.com/ClusterLabs/pacemaker/releases/tag/Pa
    cemaker-2.0.5-rc3

  - Corosync in Fedora now provides corosync-devel as well
    in isa-flavor

** Sun Nov 1 2020 Klaus Wenninger <kwenning@redhat.com> -
2.0.5-0.5.rc2 **

  - Update for new upstream tarball for release candidate:
    Pacemaker-2.0.5-rc2, includes fix for CVE-2020-25654 for
    full details, see included ChangeLog file or
    https://github.com/ClusterLabs/pacemaker/releases/tag/Pa
    cemaker-2.0.5-rc2

  - Remove dependencies to nagios-plugins from
    metadata-package

  - some sync with structure of upstream spec-file

  - removed some legacy conditionals

  - added with-cibsecrets

  - enable some basic gating-tests

  - remove building documentation using publican from ELN

  - rename doc-dir for ELN

----

  - Update for new upstream tarball for release candidate:
    Pacemaker-2.0.5-rc2, includes fix for CVE-2020-25654 for
    full details, see included ChangeLog file or
    https://github.com/ClusterLabs/pacemaker/releases/tag/Pa
    cemaker-2.0.5-rc2

  - Remove dependencies to nagios-plugins from
    metadata-package

  - some sync with structure of upstream spec-file

  - removed some legacy conditionals

  - added with-cibsecrets

  - enable some basic gating-tests

  - remove building documentation using publican from ELN

  - rename doc-dir for ELN

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-3d0e38b9e7");
  script_set_attribute(attribute:"solution", value:
"Update the affected pacemaker package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25654");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pacemaker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 33", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC33", reference:"pacemaker-2.0.5-0.7.rc3.fc33")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker");
}
