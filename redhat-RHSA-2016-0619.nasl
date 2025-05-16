#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0619. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90496);
  script_version("2.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2015-5370",
    "CVE-2016-2110",
    "CVE-2016-2111",
    "CVE-2016-2112",
    "CVE-2016-2115",
    "CVE-2016-2118"
  );
  script_xref(name:"RHSA", value:"2016:0619");

  script_name(english:"RHEL 6 : samba (RHSA-2016:0619)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for samba.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2016:0619 advisory.

    Samba is an open-source implementation of the Server Message Block (SMB) protocol and the related Common
    Internet File System (CIFS) protocol, which allow PC-compatible machines to share files, printers, and
    various information.

    Security Fix(es):

    * Multiple flaws were found in Samba's DCE/RPC protocol implementation. A remote, authenticated attacker
    could use these flaws to cause a denial of service against the Samba server (high CPU load or a crash) or,
    possibly, execute arbitrary code with the permissions of the user running Samba (root). This flaw could
    also be used to downgrade a secure DCE/RPC connection by a man-in-the-middle attacker taking control of an
    Active Directory (AD) object and compromising the security of a Samba Active Directory Domain Controller
    (DC). (CVE-2015-5370)

    Note: While Samba packages as shipped in Red Hat Enterprise Linux do not support running Samba as an AD
    DC, this flaw applies to all roles Samba implements.

    * A protocol flaw, publicly referred to as Badlock, was found in the Security Account Manager Remote
    Protocol (MS-SAMR) and the Local Security Authority (Domain Policy) Remote Protocol (MS-LSAD). Any
    authenticated DCE/RPC connection that a client initiates against a server could be used by a man-in-the-
    middle attacker to impersonate the authenticated user against the SAMR or LSA service on the server. As a
    result, the attacker would be able to get read/write access to the Security Account Manager database, and
    use this to reveal all passwords or any other potentially sensitive information in that database.
    (CVE-2016-2118)

    * Several flaws were found in Samba's implementation of NTLMSSP authentication. An unauthenticated, man-
    in-the-middle attacker could use this flaw to clear the encryption and integrity flags of a connection,
    causing data to be transmitted in plain text. The attacker could also force the client or server into
    sending data in plain text even if encryption was explicitly requested for that connection.
    (CVE-2016-2110)

    * It was discovered that Samba configured as a Domain Controller would establish a secure communication
    channel with a machine using a spoofed computer name. A remote attacker able to observe network traffic
    could use this flaw to obtain session-related information about the spoofed machine. (CVE-2016-2111)

    * It was found that Samba's LDAP implementation did not enforce integrity protection for LDAP connections.
    A man-in-the-middle attacker could use this flaw to downgrade LDAP connections to use no integrity
    protection, allowing them to hijack such connections. (CVE-2016-2112)

    * It was found that Samba did not enable integrity protection for IPC traffic by default. A man-in-the-
    middle attacker could use this flaw to view and modify the data sent between a Samba server and a client.
    (CVE-2016-2115)

    Red Hat would like to thank the Samba project for reporting these issues. Upstream acknowledges Jouni
    Knuutinen (Synopsis) as the original reporter of CVE-2015-5370; and Stefan Metzmacher (SerNet) as the
    original reporter of CVE-2016-2118, CVE-2016-2110, CVE-2016-2112, and CVE-2016-2115.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://badlock.org/");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2016/rhsa-2016_0619.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbff30c3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/badlock");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1309987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1311893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1311902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1311903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1312084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1317990");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/2253041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/2243351");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:0619");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL samba package based on the guidance in RHSA-2016:0619.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2118");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(290, 300);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6.2','6.4','6.5','6.6'])) audit(AUDIT_OS_NOT, 'Red Hat 6.2 / 6.4 / 6.5 / 6.6', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.2/x86_64/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/os',
      'content/aus/rhel/server/6/6.2/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.2/x86_64/os',
      'content/aus/rhel/server/6/6.2/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libsmbclient-3.6.23-30.el6_2', 'sp':'2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_2', 'sp':'2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_2', 'sp':'2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_2', 'sp':'2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_2', 'sp':'2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.23-30.el6_2', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.4/x86_64/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/os',
      'content/aus/rhel/server/6/6.4/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.4/x86_64/os',
      'content/aus/rhel/server/6/6.4/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libsmbclient-3.6.23-30.el6_4', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_4', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_4', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_4', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_4', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.23-30.el6_4', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.5/x86_64/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/os',
      'content/aus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.5/x86_64/os',
      'content/aus/rhel/server/6/6.5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libsmbclient-3.6.23-30.el6_5', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_5', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_5', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_5', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_5', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.23-30.el6_5', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.6/x86_64/debug',
      'content/aus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.6/x86_64/optional/os',
      'content/aus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.6/x86_64/os',
      'content/aus/rhel/server/6/6.6/x86_64/source/SRPMS',
      'content/eus/rhel/computenode/6/6.6/x86_64/debug',
      'content/eus/rhel/computenode/6/6.6/x86_64/optional/debug',
      'content/eus/rhel/computenode/6/6.6/x86_64/optional/os',
      'content/eus/rhel/computenode/6/6.6/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/6/6.6/x86_64/os',
      'content/eus/rhel/computenode/6/6.6/x86_64/sfs/debug',
      'content/eus/rhel/computenode/6/6.6/x86_64/sfs/os',
      'content/eus/rhel/computenode/6/6.6/x86_64/sfs/source/SRPMS',
      'content/eus/rhel/computenode/6/6.6/x86_64/source/SRPMS',
      'content/eus/rhel/power/6/6.6/ppc64/debug',
      'content/eus/rhel/power/6/6.6/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.6/ppc64/optional/os',
      'content/eus/rhel/power/6/6.6/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.6/ppc64/os',
      'content/eus/rhel/power/6/6.6/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.6/i386/debug',
      'content/eus/rhel/server/6/6.6/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.6/i386/highavailability/os',
      'content/eus/rhel/server/6/6.6/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.6/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.6/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.6/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.6/i386/optional/debug',
      'content/eus/rhel/server/6/6.6/i386/optional/os',
      'content/eus/rhel/server/6/6.6/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.6/i386/os',
      'content/eus/rhel/server/6/6.6/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.6/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.6/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.6/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.6/x86_64/debug',
      'content/eus/rhel/server/6/6.6/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.6/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.6/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.6/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.6/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.6/x86_64/optional/os',
      'content/eus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.6/x86_64/os',
      'content/eus/rhel/server/6/6.6/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.6/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.6/x86_64/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.6/x86_64/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.6/x86_64/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.6/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.6/s390x/debug',
      'content/eus/rhel/system-z/6/6.6/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.6/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.6/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.6/s390x/os',
      'content/eus/rhel/system-z/6/6.6/s390x/source/SRPMS',
      'content/tus/rhel/server/6/6.6/x86_64/debug',
      'content/tus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/tus/rhel/server/6/6.6/x86_64/optional/os',
      'content/tus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/6/6.6/x86_64/os',
      'content/tus/rhel/server/6/6.6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libsmbclient-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libsmbclient-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-client-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-common-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-doc-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-domainjoin-gui-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-glusterfs-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-swat-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-clients-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-devel-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.23-30.el6_6', 'sp':'6', 'cpu':'i686', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.23-30.el6_6', 'sp':'6', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.23-30.el6_6', 'sp':'6', 'cpu':'s390x', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'samba-winbind-krb5-locator-3.6.23-30.el6_6', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE}
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
