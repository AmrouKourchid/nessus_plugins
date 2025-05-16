#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:0242. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210298);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2017-1000385");
  script_xref(name:"RHSA", value:"2018:0242");

  script_name(english:"RHEL 7 : erlang (RHSA-2018:0242)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for erlang.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2018:0242 advisory.

    Erlang is a general-purpose programming language and runtime environment. Erlang has built-in support for
    concurrency, distribution and fault tolerance.

    Security Fix(es):

    * An erlang TLS server configured with cipher suites using RSA key exchange, may be vulnerable to an
    Adaptive Chosen Ciphertext attack (AKA Bleichenbacher attack) against RSA. This may result in plain-text
    recovery of encrypted messages and/or a man-in-the-middle (MiTM) attack, despite the attacker not having
    gained access to the servers private key itself. (CVE-2017-1000385)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1520400");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_0242.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327b6392");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0242");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL erlang package based on the guidance in RHSA-2018:0242.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000385");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(300);
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-asn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-cosEvent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-cosEventDomain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-cosFileTransfer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-cosNotification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-cosProperty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-cosTime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-cosTransactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-diameter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-edoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-eldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-erl_docgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-erl_interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-erts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-eunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-hipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-ic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-inets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-mnesia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-orber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-os_mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-ose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-otp_mibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-parsetools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-percept");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-public_key");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-runtime_tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-syntax_tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:erlang-xmerl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

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

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2017-1000385');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2018:0242');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'erlang-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-asn1-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-asn1-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-compiler-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-compiler-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosEvent-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosEvent-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosEventDomain-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosEventDomain-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosFileTransfer-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosFileTransfer-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosNotification-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosNotification-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosProperty-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosProperty-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosTime-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosTime-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosTransactions-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-cosTransactions-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-crypto-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-crypto-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-diameter-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-diameter-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-edoc-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-edoc-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-eldap-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-eldap-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-erl_docgen-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-erl_docgen-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-erl_interface-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-erl_interface-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-erts-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-erts-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-eunit-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-eunit-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-hipe-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-hipe-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-ic-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-ic-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-inets-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-inets-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-kernel-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-kernel-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-mnesia-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-mnesia-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-odbc-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-odbc-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-orber-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-orber-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-os_mon-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-os_mon-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-ose-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-ose-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-otp_mibs-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-otp_mibs-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-parsetools-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-parsetools-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-percept-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-percept-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-public_key-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-public_key-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-runtime_tools-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-runtime_tools-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-sasl-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-sasl-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-snmp-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-snmp-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-ssh-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-ssh-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-ssl-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-ssl-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-stdlib-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-stdlib-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-syntax_tools-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-syntax_tools-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-tools-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-tools-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-xmerl-18.3.4.7-1.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'},
      {'reference':'erlang-xmerl-18.3.4.7-1.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openstack-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'erlang / erlang-asn1 / erlang-compiler / erlang-cosEvent / etc');
}
