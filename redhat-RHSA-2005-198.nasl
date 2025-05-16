#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:198. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18443);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2005-0605");
  script_xref(name:"RHSA", value:"2005:198");

  script_name(english:"RHEL 4 : xorg-x11 (RHSA-2005:198)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for xorg-x11.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2005:198 advisory.

    X.Org X11 is the X Window System which provides the core functionality
    of the Linux GUI desktop.

    An integer overflow flaw was found in libXpm, which is used by some
    applications for loading of XPM images. An attacker could create a
    carefully crafted XPM file in such a way that it could cause an application
    linked with libXpm to execute arbitrary code when the file was opened by a
    victim. The Common Vulnerabilities and Exposures project  (cve.mitre.org)
    has assigned the name CAN-2005-0605 to this issue.

    Since the initial release of Red Hat Enterprise Linux 4, a number of issues
    have been addressed in the X.Org X11 X Window System.  This erratum also
    updates X11R6.8 to the latest stable point release (6.8.2), which includes
    various stability and reliability fixes including (but not limited to) the
    following:

    - The 'radeon' driver has been modified to disable RENDER acceleration
      by default, due to a bug in the implementation which has not yet
      been isolated.  This can be manually re-enabled by using the
      following option in the device section of the X server config file:

        Option RenderAccel

    - The 'vmware' video driver is now available on 64-bit AMD64 and
      compatible systems.

    - The Intel 'i810' video driver is now available on 64-bit EM64T
      systems.

    - Stability fixes in the X Server's PCI handling layer for 64-bit systems,
      which resolve some issues reported by vesa and nv driver users.

    - Support for Hewlett Packard's Itanium ZX2 chipset.

    - Nvidia nv video driver update provides support for some of
      the newer Nvidia chipsets, as well as many stability and reliability
      fixes.

    - Intel i810 video driver stability update, which fixes the widely
      reported i810/i815 screen refresh issues many have experienced.

    - Packaging fixes for multilib systems, which permit both 32-bit
      and 64-bit X11 development environments to be simultaneously installed
      without file conflicts.

    In addition to the above highlights, the X.Org X11 6.8.2 release has a
    large number of additional stability fixes which resolve various other
    issues reported since the initial release of Red Hat Enterprise Linux 4.

    All users of X11 should upgrade to these updated packages, which resolve
    these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2005/rhsa-2005_198.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47284e6e");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=136941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=143910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=150036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=157962");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2005:198");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL xorg-x11 package based on the guidance in RHSA-2005:198.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0605");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-14-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-14-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-15-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-15-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-2-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-2-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-9-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-ISO8859-9-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-cyrillic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-syriac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg-truetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-deprecated-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-deprecated-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fonts-xorg");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2005-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '4')) audit(AUDIT_OS_NOT, 'Red Hat 4.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/as/4/4AS/i386/os',
      'content/dist/rhel/as/4/4AS/i386/source/SRPMS',
      'content/dist/rhel/as/4/4AS/x86_64/os',
      'content/dist/rhel/as/4/4AS/x86_64/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/i386/os',
      'content/dist/rhel/desktop/4/4Desktop/i386/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/x86_64/os',
      'content/dist/rhel/desktop/4/4Desktop/x86_64/source/SRPMS',
      'content/dist/rhel/es/4/4ES/i386/os',
      'content/dist/rhel/es/4/4ES/i386/source/SRPMS',
      'content/dist/rhel/es/4/4ES/x86_64/os',
      'content/dist/rhel/es/4/4ES/x86_64/source/SRPMS',
      'content/dist/rhel/power/4/4AS/ppc/os',
      'content/dist/rhel/power/4/4AS/ppc/source/SRPMS',
      'content/dist/rhel/system-z/4/4AS/s390/os',
      'content/dist/rhel/system-z/4/4AS/s390/source/SRPMS',
      'content/dist/rhel/system-z/4/4AS/s390x/os',
      'content/dist/rhel/system-z/4/4AS/s390x/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/i386/os',
      'content/dist/rhel/ws/4/4WS/i386/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/x86_64/os',
      'content/dist/rhel/ws/4/4WS/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'fonts-xorg-100dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-75dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-base-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-cyrillic-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-ISO8859-14-100dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-ISO8859-14-75dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-ISO8859-15-100dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-ISO8859-15-75dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-ISO8859-2-100dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-ISO8859-2-75dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-ISO8859-9-100dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-ISO8859-9-75dpi-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-syriac-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fonts-xorg-truetype-6.8.1.1-1.EL.1', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-6.8.2-1.EL.13.6', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-deprecated-libs-devel-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-devel-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-devel-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-devel-6.8.2-1.EL.13.6', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-devel-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-devel-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-devel-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-doc-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-doc-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-doc-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-font-utils-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-font-utils-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-font-utils-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-font-utils-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-font-utils-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-libs-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-libs-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-libs-6.8.2-1.EL.13.6', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-libs-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-libs-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-libs-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGL-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Mesa-libGLU-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-sdk-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-sdk-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-sdk-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-tools-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-tools-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-tools-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-tools-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-tools-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-twm-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-twm-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-twm-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-twm-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-twm-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xauth-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xauth-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xauth-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xauth-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xauth-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xdm-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xdm-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xdm-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xdm-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xdm-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xdmx-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xdmx-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xdmx-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xdmx-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xdmx-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xfs-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xfs-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xfs-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xfs-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-xfs-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xnest-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xnest-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xnest-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xnest-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xnest-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xvfb-6.8.2-1.EL.13.6', 'cpu':'i386', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xvfb-6.8.2-1.EL.13.6', 'cpu':'ppc', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xvfb-6.8.2-1.EL.13.6', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xvfb-6.8.2-1.EL.13.6', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'xorg-x11-Xvfb-6.8.2-1.EL.13.6', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fonts-xorg-100dpi / fonts-xorg-75dpi / fonts-xorg-ISO8859-14-100dpi / etc');
}
