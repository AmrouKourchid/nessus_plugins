#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4670.
##

include('compat.inc');

if (description)
{
  script_id(180950);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2016-10735",
    "CVE-2018-14040",
    "CVE-2018-14042",
    "CVE-2018-20676",
    "CVE-2018-20677",
    "CVE-2019-8331",
    "CVE-2019-11358",
    "CVE-2020-1722",
    "CVE-2020-11022"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Linux 8 : idm:DL1 / and / idm:client (ELSA-2020-4670)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4670 advisory.

    bind-dyndb-ldap
    [11.3-1]
    - New upstream release
    - Resolves: rhbz#1845211

    ipa
    [4.8.7-12.0.1]
    - Set IPAPLATFORM=rhel when build on Oracle Linux [Orabug: 29516674]

    [4.8.7-12]
    - Require selinux sub package in the proper version
      Related: RHBZ#1868432
    - SELinux: do not double-define node_t and pki_tomcat_cert_t
      Related: RHBZ#1868432
    - SELinux: add dedicated policy for ipa-pki-retrieve-key + ipatests
      Related: RHBZ#1868432
    - dogtaginstance.py: add --debug to pkispawn
      Resolves: RHBZ#1879604

    [4.8.7-11]
    - SELinux Policy: let custodia replicate keys
      Resolves: RHBZ#1868432

    [4.8.7-10]
    - Set mode of /etc/ipa/ca.crt to 0644 in CA-less installations
      Resolves: RHBZ#1870202

    [4.8.7-9]
    - CAless installation: set the perms on KDC cert file
      Resolves: RHBZ#1863616
    - EPN: handle empty attributes
      Resolves: RHBZ#1866938
    - IPA-EPN: enhance input validation
      Resolves: RHBZ#1866291
    - EPN: enhance input validation
      Resolves: RHBZ#1863079
    - Require new samba build 4.12.3-52
      Related: RHBZ#1868558
    - Require new selinux-policy build 3.14.3-52
      Related: RHBZ#1869311

    [4.8.7-8]
    - [WebUI] IPA Error 3007: RequirmentError while adding members in
      User ID overrides tab (updated)
      Resolves: RHBZ#1757045
    - ipa-client-install: use the authselect backup during uninstall
      Resolves: RHBZ#1810179
    - Replace SSLCertVerificationError with CertificateError for py36
      Resolves: RHBZ#1858318
    - Fix AVC denial during ipa-adtrust-install --add-agents
      Resolves: RHBZ#1859213

    [4.8.7-7]
    - replica install failing with avc denial for custodia component
      Resolves: RHBZ#1857157

    [4.8.7-6]
    - selinux dont audit rules deny fetching trust topology
      Resolves: RHBZ#1845596
    - fix iPAddress cert issuance for >1 host/service
      Resolves: RHBZ#1846352
    - Specify cert_paths when calling PKIConnection
      Resolves: RHBZ#1849155
    - Update crypto policy to allow AD-SUPPORT when installing IPA
      Resolves: RHBZ#1851139
    - Add version to ipa-idoverride-memberof obsoletes
      Related: RHBZ#1846434

    [4.8.7-5]
    - Add missing ipa-selinux package
      Resolves: RHBZ#1853263

    [4.8.7-4]
    - Remove client-epn left over files for ONLY_CLIENT
      Related: RHBZ#1847999

    [4.8.7-3]
    - [WebUI] IPA Error 3007: RequirmentError while adding members in
      User ID overrides tab
      Resolves: RHBZ#1757045
    - EPN does not ship its default configuration ( /etc/ipa/epn.conf ) in
      freeipa-client-epn
      Resolves: RHBZ#1847999
    - FreeIPA - Utilize 256-bit AJP connector passwords
      Resolves: RHBZ#1849914
    - ipa: typo issue in ipanthomedirectoryrive deffinition
      Resolves: RHBZ#1851411

    [4.8.7-2]
    - Remove ipa-idoverride-memberof as superceded by ipa-server 4.8.7
      Resolves: RHBZ#1846434

    [4.8.7-1]
    - Upstream release FreeIPA 4.8.7
    - Require new samba build 4.12.3-0
      Related: RHBZ#1818765
    - New client-epn sub package
      Resolves: RHBZ#913799

    ipa-healthcheck
    [0.4-6]
    - The core subpackage can be installed standalone, drop the Requires
      on the base package. (#1852244)
    - Add Conflicts < 0.4 to to core to allow downgrading with
      --allowerasing (#1852244)

    [0.4-5]
    - Remove the Obsoletes < 0.4 and add same-version Requires to each
      subpackage so that upgrades from 0.3 will work (#1852244)

    opendnssec
    [2.1.6-2]
    - Resolves: rhbz#1831732 AVC avc: denied { dac_override } for comm=ods-enforcerd

    [2.1.6-1]
    - Resolves: rhbz#1759888 Rebase OpenDNSSEC to 2.1

    slapi-nis
    [0.56.5-4]
    - Ignore unmatched searches
    - Resolves: rhbz#1874015

    [0.56.5-3]
    - Fix memory leaks in ID views processing
    - Resolves: rhbz#1875348

    [0.56.5-2]
    - Initialize map lock in NIS plugin
    - Resolves: rhbz#1832331

    [0.56.5-1]
    - Upstream release 0.56.5
    - Resolves: rhbz#1751295: (2) When sync-repl is enabled, slapi-nis can deadlock during retrochanglog
    trimming
    - Resolves: rhbz#1768156: ERR - schemacompat - map rdlock: old way MAP_MONITOR_DISABLED

    softhsm
    [2.6.0-3]
    - Fixes: rhbz#1834909 - softhsm use-after-free on process exit
    - Synchronize the final fix with Fedora

    [2.6.0-2]
    - Fixes: rhbz#1834909 - softhsm use-after-free on process exit

    [2.6.0-1]
    - Fixes: rhbz#1818877 - rebase to softhsm 2.6.0+
    - Fixes: rhbz#1701233 - support setting supported signature methods on the token

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4670.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-epn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-healthcheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-healthcheck-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:opendnssec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-custodia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-jwcrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-kdcproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-pyusb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-qrcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-qrcode-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-yubico");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slapi-nis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:softhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:softhsm-devel");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/idm');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:DL1');
if ('DL1' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module idm:' + module_ver);

var appstreams = {
    'idm:DL1': [
      {'reference':'bind-dyndb-ldap-11.3-1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'custodia-0.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-common-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-epn-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-samba-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-common-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-0.4-6.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-core-0.4-6.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-python-compat-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-selinux-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-common-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-dns-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-trust-ad-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'opendnssec-2.1.6-2.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-custodia-0.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaclient-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipalib-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaserver-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-jwcrypto-0.5.0-1.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-kdcproxy-0.4-5.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyusb-1.0.0-9.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-5.1-12.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-core-5.1-12.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-yubico-1.3.2-9.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slapi-nis-0.56.5-4.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-2.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-devel-2.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'bind-dyndb-ldap-11.3-1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'custodia-0.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-common-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-epn-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-client-samba-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-common-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-0.4-6.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-healthcheck-core-0.4-6.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-python-compat-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-selinux-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-common-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-dns-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ipa-server-trust-ad-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'opendnssec-2.1.6-2.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-custodia-0.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaclient-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipalib-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-ipaserver-4.8.7-12.0.1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-jwcrypto-0.5.0-1.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-kdcproxy-0.4-5.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pyusb-1.0.0-9.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-5.1-12.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qrcode-core-5.1-12.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-yubico-1.3.2-9.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slapi-nis-0.56.5-4.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-2.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'softhsm-devel-2.6.0-3.module+el8.3.0+7868+2151076c', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module idm:DL1');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind-dyndb-ldap / custodia / ipa-client / etc');
}
