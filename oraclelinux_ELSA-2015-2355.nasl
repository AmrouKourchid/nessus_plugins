#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2355 and 
# Oracle Linux Security Advisory ELSA-2015-2355 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87095);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2015-5292");
  script_xref(name:"RHSA", value:"2015:2355");

  script_name(english:"Oracle Linux 7 : sssd (ELSA-2015-2355)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2015-2355 advisory.

    [1.13.0-40]
    - Resolves: rhbz#1270827 - local overrides: don't contact server with
                               overridden name/id

    [1.13.0-39]
    - Resolves: rhbz#1267837 - sssd_be crashed in ipa_srv_ad_acct_lookup_step

    [1.13.0-38]
    - Resolves: rhbz#1267176 - Memory leak / possible DoS with krb auth.

    [1.13.0-37]
    - Resolves: rhbz#1267836 - PAM responder crashed if user was not set

    [1.13.0-36]
    - Resolves: rhbz#1266107 - AD: Conditional jump or move depends on
                               uninitialised value

    [1.13.0-35]
    - Resolves: rhbz#1250135 - Detect re-established trusts in the IPA
                               subdomain code

    [1.13.0-34]
    - Fix a Coverity warning in dyndns code
    - Resolves: rhbz#1261155 - nsupdate exits on first GSSAPI error instead
                               of processing other commands

    [1.13.0-33]
    - Resolves: rhbz#1261155 - nsupdate exits on first GSSAPI error instead
                               of processing other commands

    [1.13.0-32]
    - Resolves: rhbz#1263735 - Could not resolve AD user from root domain

    [1.13.0-31]
    - Remove -d from sss_override manpage
    - Related: rhbz#1259512 - sss_override : The local override user is not found

    [1.13.0-30]
    - Patches required for better handling of failover with one-way trusts
    - Related: rhbz#1250135 - Detect re-established trusts in the IPA subdomain
                              code

    [1.13.0-29]
    - Resolves: rhbz#1263587 - sss_override --name doesn't work with RFC2307
                               and ghost users

    [1.13.0-28]
    - Resolves: rhbz#1259512 - sss_override : The local override user is not found

    [1.13.0-27]
    - Resolves: rhbz#1260027 - sssd_be memory leak with sssd-ad in GPO code

    [1.13.0-26]
    - Resolves: rhbz#1256398 - sssd cannot resolve user names containing
                               backslash with ldap provider

    [1.13.0-25]
    - Resolves: rhbz#1254189 - sss_override contains an extra parameter --debug
                               but is not listed in the man page or in
                               the arguments help

    [1.13.0-24]
    - Resolves: rhbz#1254518 - Fix crash in nss responder

    [1.13.0-23]
    - Support import/export for local overrides
    - Support FQDNs for local overrides
    - Resolves: rhbz#1254184 - sss_override does not work correctly when
                               'use_fully_qualified_names = True'

    [1.13.0-22]
    - Resolves: rhbz#1244950 - Add index for 'objectSIDString' and maybe to
                               other cache attributes

    [1.13.0-21]
    - Resolves: rhbz#1250415 - sssd: p11_child hardening

    [1.13.0-20]
    - Related: rhbz#1250135 - Detect re-established trusts in the IPA
                              subdomain code

    [1.13.0-19]
    - Resolves: rhbz#1202724 - [RFE] Add a way to lookup users based on CAC
                               identity certificates

    [1.13.0-18]
    - Resolves: rhbz#1232950 - [IPA/IdM] sudoOrder not honored as expected

    [1.13.0-17]
    - Fix wildcard_limit=0
    - Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface

    [1.13.0-16]
    - Fix race condition in invalidating the memory cache
    - Related: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups

    [1.13.0-15]
    - Resolves: rhbz#1249015 - KDC proxy not working with SSSD krb5_use_kdcinfo
                               enabled

    [1.13.0-14]
    - Bump release number
    - Related: rhbz#1246489 - sss_obfuscate fails with 'ImportError: No module
                              named pysss'

    [1.13.0-13]
    - Fix missing dependency of sssd-tools
    - Resolves: rhbz#1246489 - sss_obfuscate fails with 'ImportError: No module
                               named pysss'

    [1.13.0-12]
    - More memory cache related fixes
    - Related: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups

    [1.13.0-11]
    - Remove binary blob from SC patches as patch(1) can't handle those
    - Related: rhbz#854396 - [RFE] Support for smart cards

    [1.13.0-10]
    - Resolves: rhbz#1244949 - getgrgid for user's UID on a trust client
                               prevents getpw*

    [1.13.0-9]
    - Fix memory cache integration tests
    - Resolves: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups
    - Resolves: rhbz#854396 - [RFE] Support for smart cards

    [1.13.0-8]
    - Remove OTP from PAM stack correctly
    - Related: rhbz#1200873 - [RFE] Allow smart multi step prompting when
                              user logs in with password and token code from IPA
    - Handle sssd-owned keytabs when sssd runs as root
    - Related: rhbz#1205144 - RFE: Support one-way trusts for IPA

    [1.13.0-7]
    - Resolves: rhbz#1183747 - [FEAT] UID and GID mapping on individual clients

    [1.13.0-6]
    - Resolves: rhbz#1206565 - [RFE] Add dualstack and multihomed support
    - Resolves: rhbz#1187146 - If v4 address exists, will not create nonexistant
                               v6 in ipa domain

    [1.13.0-5]
    - Resolves: rhbz#1242942 - well-known SID check is broken for NetBIOS prefixes

    [1.13.0-4]
    - Resolves: rhbz#1234722 - sssd ad provider fails to start in rhel7.2

    [1.13.0-3]
    - Add support for InfoPipe wildcard requests
    - Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface

    [1.13.0-2]
    - Also package the initgr memcache
    - Related: rhbz#1205554 - Rebase SSSD to 1.13.x

    [1.13.0-1]
    - Rebase to 1.13.0 upstream
    - Related: rhbz#1205554 - Rebase SSSD to 1.13.x
    - Resolves: rhbz#910187 - [RFE] authenticate against cache in SSSD
    - Resolves: rhbz#1206575 - [RFE] The fast memory cache should cache initgroups

    [1.13.0.3alpha]
    - Don't default to SSSD user
    - Related: rhbz#1205554 - Rebase SSSD to 1.13.x

    [1.13.0.2alpha]
    - Related: rhbz#1205554 - Rebase SSSD to 1.13.x
    - GPO default should be permissve

    [1.13.0.1alpha]
    - Resolves: rhbz#1205554 - Rebase SSSD to 1.13.x
    - Relax the libldb requirement
    - Resolves: rhbz#1221992 - sssd_be segfault at 0 ip sp error 6 in
                               libtevent.so.0.9.21
    - Resolves: rhbz#1221839 - SSSD group enumeration inconsistent due to
                               binary SIDs
    - Resolves: rhbz#1219285 - Unable to resolve group memberships for AD
                               users when using sssd-1.12.2-58.el7_1.6.x86_64
                               client in combination with
                               ipa-server-3.0.0-42.el6.x86_64 with AD Trust
    - Resolves: rhbz#1217559 - [RFE] Support GPOs from different domain controllers
    - Resolves: rhbz#1217350 - ignore_group_members doesn't work for subdomains
    - Resolves: rhbz#1217127 - Override for IPA users with login does not list
                               user all groups
    - Resolves: rhbz#1216285 - autofs provider fails when default_domain_suffix
                               and use_fully_qualified_names set
    - Resolves: rhbz#1214719 - Group resolution is inconsistent with group
                               overrides
    - Resolves: rhbz#1214718 - Overridde with --login fails trusted adusers
                               group membership resolution
    - Resolves: rhbz#1214716 - idoverridegroup for ipa group with --group-name
                               does not work
    - Resolves: rhbz#1214337 - Overrides with --login work in second attempt
    - Resolves: rhbz#1212489 - Disable the cleanup task by default
    - Resolves: rhbz#1211830 - external users do not resolve with
                               'default_domain_suffix' set in IPA server sssd.conf
    - Resolves: rhbz#1210854 - Only set the selinux context if the context
                               differs from the local one
    - Resolves: rhbz#1209483 - When using id_provider=proxy with
                               auth_provider=ldap, it does not work as expected
    - Resolves: rhbz#1209374 - Man sssd-ad(5) lists Group Policy Management
                               Editor naming for some policies but not for all
    - Resolves: rhbz#1208507 - sysdb sudo search doesn't escape special characters
    - Resolves: rhbz#1206571 - [RFE] Expose D-BUS interface
    - Resolves: rhbz#1206566 - SSSD does not update Dynamic DNS records if
                               the IPA domain differs from machine hostname's
                               domain
    - Resolves: rhbz#1206189 - [bug] sssd always appends default_domain_suffix
                               when checking for host keys
    - Resolves: rhbz#1204203 - sssd crashes intermittently
    - Resolves: rhbz#1203945 - [FJ7.0 Bug]: getgrent returns error because
                               sss is written in nsswitch.conf as default
    - Resolves: rhbz#1203642 - GPO access control looks for computer object
                               in user's domain only
    - Resolves: rhbz#1202245 - SSSD's HBAC processing is not permissive enough
                               with broken replication entries
    - Resolves: rhbz#1201271 - sssd_nss segfaults if initgroups request is by
                               UPN and doesn't find anything
    - Resolves: rhbz#1200873 - [RFE] Allow smart multi step prompting when
                               user logs in with password and token code from IPA
    - Resolves: rhbz#1199541 - Read and use the TTL value when resolving a
                               SRV query
    - Resolves: rhbz#1199533 - [RFE] Implement background refresh for users,
                               groups or other cache objects
    - Resolves: rhbz#1199445 - Does sssd-ad use the most suitable attribute
                               for group name?
    - Resolves: rhbz#1198477 - ccname_file_dummy is not unlinked on error
    - Resolves: rhbz#1187103 - [RFE] User's home directories are not taken
                               from AD when there is an IPA trust with AD
    - Resolves: rhbz#1185536 - In ipa-ad trust, with 'default_domain_suffix' set
                               to AD domain, IPA user are not able to log unless
                               use_fully_qualified_names is set
    - Resolves: rhbz#1175760 - [RFE] Have OpenLDAP lock out ssh keys when
                               account naturally expires
    - Resolves: rhbz#1163806 - [RFE]ad provider dns_discovery_domain option:
                               kerberos discovery is not using this option
    - Resolves: rhbz#1205160 - Complain loudly if backend doesn't start due
                               to missing or invalid keytab

    [1.12.2-61]
    - Resolves: rhbz#1226119 - Properly handle AD's binary objectGUID

    [1.12.2-60]
    - Filter out domain-local groups during AD initgroups operation
    - Related: rhbz#1201840 - SSSD downloads too much information when fetching
                              information about groups

    [1.12.2-59]
    - Resolves: rhbz#1201840 - SSSD downloads too much information when fetching
                               information about groups

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-2355.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'libipa_hbac-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libipa_hbac-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libsss_nss_idmap-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-murmur-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sssdconfig-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.13.0-40.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libipa_hbac-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libsss_nss_idmap-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-murmur-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sssdconfig-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.13.0-40.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libipa_hbac / libipa_hbac-devel / libsss_idmap / etc');
}
