#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-0975.
##

include('compat.inc');

if (description)
{
  script_id(181078);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2010-4341");

  script_name(english:"Oracle Linux 5 : sssd (ELSA-2011-0975)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2011-0975 advisory.

    [1.5.1-37]
    - Reverts:  rhbz#680443 - Dynamic DNS update fails if multiple servers are
    -                         given in ipa_server config option

    [1.5.1-36]
    - Resolves: rhbz#709333 - sssd. should require sssd-client.

    [1.5.1-35]
    - Resolves: rhbz#707340 - latest sssd fails if ldap_default_authtok_type is
    -                         not mentioned
    - Resolves: rhbz#707574 - SSSD's async resolver only tries the first
    -                         nameserver in /etc/resolv.conf

    [1.5.1-34]
    - Resolves: rhbz#701702 - sssd client libraries use select() but should use
    -                         poll() instead

    [1.5.1-33]
    - Related:  rhbz#700858 - Automatic TGT renewal overwrites cached password
    - Fix segfault in TGT renewal

    [1.5.1-32]
    - Resolves: rhbz#700858 - Automatic TGT renewal overwrites cached password

    [1.5.1-30]
    - Resolves: rhbz#696979 - Filters not honoured against fully-qualified users

    [1.5.1-29]
    - Resolves: rhbz#694149 - SSSD consumes GBs of RAM, possible memory leak

    [1.5.1-28]
    - Related:  rhbz#691900 - SSSD needs to fall back to 'cn' for GECOS
    -                         information

    [1.5.1-27]
    - Related:  rhbz#694853 - SSSD crashes during getent when anonymous bind is
    -                         disabled

    [1.5.1-26]
    - Resolves: rhbz#695476 - Unable to resolve SRV record when called with
    [in ldap_uri]
    - Related:  rhbz#694853 - SSSD crashes during getent when anonymous bind is
    -                         disabled

    [1.5.1-25]
    - Resolves: rhbz#694853 - SSSD crashes during getent when anonymous bind is
    -                         disabled

    [1.5.1-24]
    - Resolves: rhbz#692960 - Process /usr/libexec/sssd/sssd_be was killed by
    -                         signal 11 (SIGSEGV)
    -                         Fix is to not attempt to resolve nameless servers

    [1.5.1-23]
    - Resolves: rhbz#691900 - SSSD needs to fall back to 'cn' for GECOS
    -                         information

    [1.5.1-21]
    - Resolves: rhbz#690867 - Groups with a zero-length memberuid attribute can
    -                         cause SSSD to stop caching and responding to
    -                         requests

    [1.5.1-20]
    - Resolves: rhbz#690287 - Traceback messages seen while interrupting
    -                         sss_obfuscate using ctrl+d
    - Resolves: rhbz#690814 - [abrt] sssd-1.2.1-28.el6_0.4: _talloc_free: Process
    -                         /usr/libexec/sssd/sssd_be was killed by signal 11
    -                         (SIGSEGV)

    [1.5.1-19]
    - Related: rhbz#690096 - SSSD should skip over groups with multiple names

    [1.5.1-18]
    - Resolves: rhbz#690093 - SSSD breaks on RDNs with a comma in them
    - Resolves: rhbz#690096 - SSSD should skip over groups with multiple names
    - Resolves: rhbz#689887 - group memberships are not populated correctly during
    -                         IPA provider initgroups
    - Resolves: rhbz#688697 - Skip users and groups that have incomplete contents
    - Resolves: rhbz#688694 - authconfig fails when access_provider is set as krb5
    -                         in sssd.conf

    [1.5.1-17]
    - Resolves: rhbz#688677 - Build SSSD in RHEL 5.7 against openldap24-libs
    - Adds support for following LDAP referrals and using Mozilla NSS for crypto
    - support

    [1.5.1-16]
    - Resolves: rhbz#683260 - sudo/ldap lookup via sssd gets stuck for 5min
    -                         waiting on netgroup
    - Resolves: rhbz#683585 - sssd consumes 100% CPU
    - Related: rhbz#680441  - sssd does not handle kerberos server IP change

    [1.5.1-15]
    - Related: rhbz#680441 - sssd does not handle kerberos server IP change
    -   SSSD was staying with the old server if it was still online

    [1.5.1-14]
    - Resolves: rhbz#682853 - IPA provider should use realm instead of ipa_domain
    -                         for base DN

    [1.5.1-13]
    - Resolves: rhbz#682803 - sssd-be segmentation fault - ipa-client on
    -                         ipa-server
    - Resolves: rhbz#680441 - sssd does not handle kerberos server IP change
    - Resolves: rhbz#680443 - Dynamic DNS update fails if multiple servers are
    -                         given in ipa_server config option
    - Resolves: rhbz#680933 - Do not delete sysdb memberOf if there is no memberOf
    -                         attribute on the server
    - Resolves: rhbz#682808 - sssd_nss core dumps with certain lookups

    [1.5.1-12]
    - Related: rhbz#679087 - SSSD IPA provider should honor the krb5_realm option
    - Related: rhbz#678615 - SSSD needs to look at IPA's compat tree for netgroups

    [1.5.1-11]
    - Resolves: rhbz#679087 - SSSD IPA provider should honor the krb5_realm option
    - Resolves: rhbz#679097 - Does not read renewable ccache at startup

    [1.5.1-10]
    - Resolves: rhbz#678606 - User information not updated on login for secondary
    -                         domains
    - Resolves: rhbz#678778 - IPA provider does not update removed group
    -                         memberships on initgroups

    [1.5.1-9]
    - Resolves: rhbz#678780 - sssd crashes at the next tgt renewals it tries
    - Resolves: rhbz#678412 - name service caches names, so id command shows
    -                         recently deleted users
    - Resolves: rhbz#678615 - SSSD needs to look at IPA's compat tree for
    -                         netgroups

    [1.5.1-8]
    - Related: rhbz#665314 - Rebase SSSD to 1.5 in RHEL 5.7
    - Fix generation of translated manpages

    [1.5.1-7]
    - Resolves: rhbz#665314 - Rebase SSSD to 1.5 in RHEL 5.7
    - Resolves: rhbz#676027 - sssd segfault when first entry of ldap_uri is
    -                         unreachable
    - Resolves: rhbz#678032 - Remove HBAC time rules from SSSD
    - Resolves: rhbz#675007 - sssd corrupts group cache
    - Resolves: rhbz#608864 - [RFE] Support obfuscated passwords in the SSSD
    -                         configuration

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0975.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected sssd, sssd-client and / or sssd-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4341");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'sssd-1.5.1-37.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.5.1-37.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.5.1-37.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.5.1-37.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.5.1-37.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.5.1-37.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sssd / sssd-client / sssd-tools');
}
