#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0137. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57969);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2010-2642",
    "CVE-2011-0433",
    "CVE-2011-0764",
    "CVE-2011-1552",
    "CVE-2011-1553",
    "CVE-2011-1554"
  );
  script_bugtraq_id(
    45678,
    46941,
    47168,
    47169
  );
  script_xref(name:"RHSA", value:"2012:0137");

  script_name(english:"RHEL 6 : texlive (RHSA-2012:0137)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for texlive.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2012:0137 advisory.

    TeX Live is an implementation of TeX. TeX takes a text file and a set of
    formatting commands as input, and creates a typesetter-independent DeVice
    Independent (DVI) file as output. The texlive packages provide a number of
    utilities, including dvips.

    TeX Live embeds a copy of t1lib. The t1lib library allows you to rasterize
    bitmaps from PostScript Type 1 fonts. The following issues affect t1lib
    code:

    Two heap-based buffer overflow flaws were found in the way t1lib processed
    Adobe Font Metrics (AFM) files. If a specially-crafted font file was opened
    by a TeX Live utility, it could cause the utility to crash or, potentially,
    execute arbitrary code with the privileges of the user running the utility.
    (CVE-2010-2642, CVE-2011-0433)

    An invalid pointer dereference flaw was found in t1lib. A specially-crafted
    font file could, when opened, cause a TeX Live utility to crash or,
    potentially, execute arbitrary code with the privileges of the user running
    the utility. (CVE-2011-0764)

    A use-after-free flaw was found in t1lib. A specially-crafted font file
    could, when opened, cause a TeX Live utility to crash or, potentially,
    execute arbitrary code with the privileges of the user running the utility.
    (CVE-2011-1553)

    An off-by-one flaw was found in t1lib. A specially-crafted font file could,
    when opened, cause a TeX Live utility to crash or, potentially, execute
    arbitrary code with the privileges of the user running the utility.
    (CVE-2011-1554)

    An out-of-bounds memory read flaw was found in t1lib. A specially-crafted
    font file could, when opened, cause a TeX Live utility to crash.
    (CVE-2011-1552)

    Red Hat would like to thank the Evince development team for reporting
    CVE-2010-2642. Upstream acknowledges Jon Larimer of IBM X-Force as the
    original reporter of CVE-2010-2642.

    All users of texlive are advised to upgrade to these updated packages,
    which contain backported patches to correct these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2012/rhsa-2012_0137.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?036fa2e9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2012:0137");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=666318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=679732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=692853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=692854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=692856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=692909");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL texlive package based on the guidance in RHSA-2012:0137.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2642");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2011-1554");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 193, 416);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpathsea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mendexk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dviutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-east-asian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/os',
      'content/dist/rhel/client/6/6Client/i386/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/os',
      'content/dist/rhel/client/6/6Client/i386/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/os',
      'content/dist/rhel/client/6/6Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/os',
      'content/dist/rhel/client/6/6Client/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/os',
      'content/dist/rhel/power/6/6Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/os',
      'content/dist/rhel/power/6/6Server/ppc64/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/os',
      'content/dist/rhel/server/6/6Server/i386/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/optional/debug',
      'content/dist/rhel/server/6/6Server/i386/optional/os',
      'content/dist/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/os',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/optional/debug',
      'content/dist/rhel/server/6/6Server/x86_64/optional/os',
      'content/dist/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/os',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/os',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/os',
      'content/dist/rhel/system-z/6/6Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/debug',
      'content/fastrack/rhel/client/6/i386/optional/debug',
      'content/fastrack/rhel/client/6/i386/optional/os',
      'content/fastrack/rhel/client/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/os',
      'content/fastrack/rhel/client/6/i386/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/os',
      'content/fastrack/rhel/client/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/os',
      'content/fastrack/rhel/client/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/debug',
      'content/fastrack/rhel/computenode/6/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/6/x86_64/optional/os',
      'content/fastrack/rhel/computenode/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/os',
      'content/fastrack/rhel/power/6/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/os',
      'content/fastrack/rhel/power/6/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/os',
      'content/fastrack/rhel/server/6/i386/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/loadbalancer/debug',
      'content/fastrack/rhel/server/6/i386/loadbalancer/os',
      'content/fastrack/rhel/server/6/i386/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/optional/debug',
      'content/fastrack/rhel/server/6/i386/optional/os',
      'content/fastrack/rhel/server/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/debug',
      'content/fastrack/rhel/server/6/i386/resilientstorage/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/os',
      'content/fastrack/rhel/server/6/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/debug',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/os',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/optional/debug',
      'content/fastrack/rhel/server/6/x86_64/optional/os',
      'content/fastrack/rhel/server/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/os',
      'content/fastrack/rhel/system-z/6/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/os',
      'content/fastrack/rhel/system-z/6/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/os',
      'content/fastrack/rhel/workstation/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/os',
      'content/fastrack/rhel/workstation/6/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/os',
      'content/fastrack/rhel/workstation/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kpathsea-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-2007-57.el6_2', 'cpu':'ppc', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-2007-57.el6_2', 'cpu':'s390', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-devel-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-devel-2007-57.el6_2', 'cpu':'ppc', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-devel-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-devel-2007-57.el6_2', 'cpu':'s390', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-devel-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kpathsea-devel-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mendexk-2.6e-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mendexk-2.6e-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mendexk-2.6e-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mendexk-2.6e-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-afm-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-afm-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-afm-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-afm-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-context-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-context-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-context-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-context-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-dvips-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-dvips-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-dvips-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-dvips-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-dviutils-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-dviutils-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-dviutils-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-dviutils-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-east-asian-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-east-asian-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-east-asian-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-east-asian-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-latex-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-latex-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-latex-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-latex-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-utils-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-utils-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-utils-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-utils-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-xetex-2007-57.el6_2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-xetex-2007-57.el6_2', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-xetex-2007-57.el6_2', 'cpu':'s390x', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'texlive-xetex-2007-57.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpathsea / kpathsea-devel / mendexk / texlive / texlive-afm / etc');
}
