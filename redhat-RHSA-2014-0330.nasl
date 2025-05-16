#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0330. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73199);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2012-6150", "CVE-2013-4496");
  script_bugtraq_id(64101, 66336);
  script_xref(name:"RHSA", value:"2014:0330");

  script_name(english:"RHEL 6 : samba and samba3x (RHSA-2014:0330)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for samba / samba3x.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:0330 advisory.

    Samba is an open-source implementation of the Server Message Block (SMB) or
    Common Internet File System (CIFS) protocol, which allows PC-compatible
    machines to share files, printers, and other information.

    It was found that certain Samba configurations did not enforce the password
    lockout mechanism. A remote attacker could use this flaw to perform
    password guessing attacks on Samba user accounts. Note: this flaw only
    affected Samba when deployed as a Primary Domain Controller.
    (CVE-2013-4496)

    A flaw was found in the way the pam_winbind module handled configurations
    that specified a non-existent group as required. An authenticated user
    could possibly use this flaw to gain access to a service using pam_winbind
    in its PAM configuration when group restriction was intended for access to
    the service. (CVE-2012-6150)

    Red Hat would like to thank the Samba project for reporting CVE-2013-4496
    and Sam Richardson for reporting CVE-2012-6150. Upstream acknowledges
    Andrew Bartlett as the original reporter of CVE-2013-4496.

    All users of Samba are advised to upgrade to these updated packages, which
    contain backported patches to correct these issues. After installing this
    update, the smb service will be restarted automatically.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_0330.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c680348b");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2012-6150");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/CVE-2013-4496");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:0330");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1036897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1072792");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL samba / samba3x packages based on the guidance in RHSA-2014:0330.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4496");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'libsmbclient-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.9-168.el6_5', 'cpu':'ppc', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.9-168.el6_5', 'cpu':'s390', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.9-168.el6_5', 'cpu':'ppc', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.9-168.el6_5', 'cpu':'s390', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.9-168.el6_5', 'cpu':'ppc', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.9-168.el6_5', 'cpu':'s390', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.9-168.el6_5', 'cpu':'ppc', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.9-168.el6_5', 'cpu':'s390', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.9-168.el6_5', 'cpu':'ppc', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.9-168.el6_5', 'cpu':'s390', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.9-168.el6_5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.9-168.el6_5', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.9-168.el6_5', 'cpu':'s390x', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.9-168.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsmbclient / libsmbclient-devel / samba / samba-client / etc');
}
