#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1008. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77012);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2014-3560");
  script_bugtraq_id(69021);
  script_xref(name:"RHSA", value:"2014:1008");

  script_name(english:"RHEL 7 : samba (RHSA-2014:1008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for samba.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2014:1008 advisory.

    Samba is an open-source implementation of the Server Message Block (SMB) or
    Common Internet File System (CIFS) protocol, which allows PC-compatible
    machines to share files, printers, and other information.

    A heap-based buffer overflow flaw was found in Samba's NetBIOS message
    block daemon (nmbd). An attacker on the local network could use this flaw
    to send specially crafted packets that, when processed by nmbd, could
    possibly lead to arbitrary code execution with root privileges.
    (CVE-2014-3560)

    This update also fixes the following bug:

    * Prior to this update, Samba incorrectly used the O_TRUNC flag when using
    the open(2) system call to access the contents of a file that was already
    opened by a different process, causing the file's previous contents to be
    removed. With this update, the O_TRUNC flag is no longer used in the above
    scenario, and file corruption no longer occurs. (BZ#1115490)

    All Samba users are advised to upgrade to these updated packages, which
    contain backported patches to correct these issues. After installing this
    update, the smb service will be restarted automatically.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_1008.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9941af92");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2014-3560");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1008");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1115490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1126010");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL samba package based on the guidance in RHSA-2014:1008.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3560");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/client/7/7.9/x86_64/debug',
      'content/dist/rhel/client/7/7.9/x86_64/optional/debug',
      'content/dist/rhel/client/7/7.9/x86_64/optional/os',
      'content/dist/rhel/client/7/7.9/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7.9/x86_64/os',
      'content/dist/rhel/client/7/7.9/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7.9/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7.9/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7.9/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power/7/7.9/ppc64/debug',
      'content/dist/rhel/power/7/7.9/ppc64/optional/debug',
      'content/dist/rhel/power/7/7.9/ppc64/optional/os',
      'content/dist/rhel/power/7/7.9/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7.9/ppc64/os',
      'content/dist/rhel/power/7/7.9/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/debug',
      'content/dist/rhel/server/7/7.9/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7.9/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7.9/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/optional/debug',
      'content/dist/rhel/server/7/7.9/x86_64/optional/os',
      'content/dist/rhel/server/7/7.9/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/os',
      'content/dist/rhel/server/7/7.9/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7.9/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7.9/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/os',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/os',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/7/7.9/x86_64/debug',
      'content/dist/rhel/workstation/7/7.9/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7.9/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7.9/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7.9/x86_64/os',
      'content/dist/rhel/workstation/7/7.9/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libsmbclient-4.1.1-37.el7_0', 'cpu':'i686', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-4.1.1-37.el7_0', 'cpu':'ppc', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-4.1.1-37.el7_0', 'cpu':'s390', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-4.1.1-37.el7_0', 'cpu':'i686', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-4.1.1-37.el7_0', 'cpu':'ppc', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-4.1.1-37.el7_0', 'cpu':'s390', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-4.1.1-37.el7_0', 'cpu':'i686', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-4.1.1-37.el7_0', 'cpu':'ppc', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-4.1.1-37.el7_0', 'cpu':'s390', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-devel-4.1.1-37.el7_0', 'cpu':'i686', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-devel-4.1.1-37.el7_0', 'cpu':'ppc', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-devel-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-devel-4.1.1-37.el7_0', 'cpu':'s390', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-devel-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwbclient-devel-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dc-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dc-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dc-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dc-libs-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dc-libs-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-dc-libs-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-devel-4.1.1-37.el7_0', 'cpu':'i686', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-devel-4.1.1-37.el7_0', 'cpu':'ppc', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-devel-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-devel-4.1.1-37.el7_0', 'cpu':'s390', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-devel-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-devel-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-libs-4.1.1-37.el7_0', 'cpu':'i686', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-libs-4.1.1-37.el7_0', 'cpu':'ppc', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-libs-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-libs-4.1.1-37.el7_0', 'cpu':'s390', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-libs-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-libs-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-pidl-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-pidl-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-pidl-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-python-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-python-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-python-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-devel-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-devel-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-test-devel-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-vfs-glusterfs-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-modules-4.1.1-37.el7_0', 'cpu':'i686', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-modules-4.1.1-37.el7_0', 'cpu':'ppc', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-modules-4.1.1-37.el7_0', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-modules-4.1.1-37.el7_0', 'cpu':'s390', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-modules-4.1.1-37.el7_0', 'cpu':'s390x', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-modules-4.1.1-37.el7_0', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_0', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsmbclient / libsmbclient-devel / libwbclient / libwbclient-devel / etc');
}
