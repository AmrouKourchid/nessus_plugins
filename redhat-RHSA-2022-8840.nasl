#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:8840. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168498);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-1292",
    "CVE-2022-2068",
    "CVE-2022-22721",
    "CVE-2022-23943",
    "CVE-2022-26377",
    "CVE-2022-27781",
    "CVE-2022-28614",
    "CVE-2022-28615",
    "CVE-2022-30522",
    "CVE-2022-31813",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208",
    "CVE-2022-32221",
    "CVE-2022-35252",
    "CVE-2022-42915",
    "CVE-2022-42916"
  );
  script_xref(name:"RHSA", value:"2022:8840");

  script_name(english:"RHEL 7 / 8 : Red Hat JBoss Core Services Apache HTTP Server 2.4.51 SP1 (RHSA-2022:8840)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Core Services Apache HTTP Server
2.4.51 SP1.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:8840 advisory.

    Red Hat JBoss Core Services is a set of supplementary software for Red Hat JBoss middleware products. This
    software, such as Apache HTTP Server, is common to multiple JBoss middleware products, and is packaged
    under Red Hat JBoss Core Services to allow for faster distribution of updates, and for a more consistent
    update experience.

    This release of Red Hat JBoss Core Services Apache HTTP Server 2.4.51 Service Pack 1 serves as a
    replacement for Red Hat JBoss Core Services Apache HTTP Server 2.4.51, and includes bug fixes and
    enhancements, which are documented in the Release Notes document linked to in the References.

    Security Fix(es):

    * httpd: mod_sed: Read/write beyond bounds (CVE-2022-23943)

    * openssl: c_rehash script allows command injection (CVE-2022-1292)

    * openssl: the c_rehash script allows command injection (CVE-2022-2068)

    * httpd: core: Possible buffer overflow with very large or unlimited LimitXMLRequestBody (CVE-2022-22721)

    * httpd: mod_proxy_ajp: Possible request smuggling (CVE-2022-26377)

    * httpd: mod_sed: DoS vulnerability (CVE-2022-30522)

    * httpd: mod_proxy: X-Forwarded-For dropped by hop-by-hop mechanism (CVE-2022-31813)

    * curl: HTTP compression denial of service (CVE-2022-32206)

    * curl: Unpreserved file permissions (CVE-2022-32207)

    * curl: FTP-KRB bad message verification (CVE-2022-32208)

    * curl: POST following PUT confusion (CVE-2022-32221)

    * curl: HTTP proxy double-free (CVE-2022-42915)

    * curl: HSTS bypass via IDN (CVE-2022-42916)

    * curl: CERTINFO never-ending busy-loop (CVE-2022-27781)

    * httpd: Out-of-bounds read via ap_rwrite() (CVE-2022-28614)

    * httpd: Out-of-bounds read in ap_strcmp_match() (CVE-2022-28615)

    * curl: control code in cookie denial of service (CVE-2022-35252)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_8840.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4eb12e55");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2064319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2064320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2082204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2094997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2095002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2095006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2095015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2095020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2099300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2099305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2099306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2120718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2135416");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:8840");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Core Services Apache HTTP Server 2.4.51 SP1 package based on the guidance in
RHSA-2022:8840.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2068");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(77, 125, 200, 281, 319, 348, 415, 440, 444, 770, 787, 789, 835, 924, 1286);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/jbcs/1/debug',
      'content/dist/layered/rhel8/x86_64/jbcs/1/os',
      'content/dist/layered/rhel8/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-curl-7.86.0-2.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-27781', 'CVE-2022-32206', 'CVE-2022-32207', 'CVE-2022-32208', 'CVE-2022-32221', 'CVE-2022-35252', 'CVE-2022-42915', 'CVE-2022-42916']},
      {'reference':'jbcs-httpd24-httpd-2.4.51-37.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.51-37.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.51-37.el8jbcs', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.51-37.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.51-37.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-libcurl-7.86.0-2.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-27781', 'CVE-2022-32206', 'CVE-2022-32207', 'CVE-2022-32208', 'CVE-2022-32221', 'CVE-2022-35252', 'CVE-2022-42915', 'CVE-2022-42916']},
      {'reference':'jbcs-httpd24-libcurl-devel-7.86.0-2.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-27781', 'CVE-2022-32206', 'CVE-2022-32207', 'CVE-2022-32208', 'CVE-2022-32221', 'CVE-2022-35252', 'CVE-2022-42915', 'CVE-2022-42916']},
      {'reference':'jbcs-httpd24-mod_http2-1.15.19-20.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-31813']},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.51-37.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.51-37.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-mod_session-2.4.51-37.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.51-37.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-openssl-1.1.1k-13.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']},
      {'reference':'jbcs-httpd24-openssl-devel-1.1.1k-13.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']},
      {'reference':'jbcs-httpd24-openssl-libs-1.1.1k-13.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']},
      {'reference':'jbcs-httpd24-openssl-perl-1.1.1k-13.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']},
      {'reference':'jbcs-httpd24-openssl-static-1.1.1k-13.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-curl-7.86.0-2.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-27781', 'CVE-2022-32206', 'CVE-2022-32207', 'CVE-2022-32208', 'CVE-2022-32221', 'CVE-2022-35252', 'CVE-2022-42915', 'CVE-2022-42916']},
      {'reference':'jbcs-httpd24-httpd-2.4.51-37.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.51-37.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.51-37.el7jbcs', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.51-37.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.51-37.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-libcurl-7.86.0-2.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-27781', 'CVE-2022-32206', 'CVE-2022-32207', 'CVE-2022-32208', 'CVE-2022-32221', 'CVE-2022-35252', 'CVE-2022-42915', 'CVE-2022-42916']},
      {'reference':'jbcs-httpd24-libcurl-devel-7.86.0-2.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-27781', 'CVE-2022-32206', 'CVE-2022-32207', 'CVE-2022-32208', 'CVE-2022-32221', 'CVE-2022-35252', 'CVE-2022-42915', 'CVE-2022-42916']},
      {'reference':'jbcs-httpd24-mod_http2-1.15.19-20.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-31813']},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.51-37.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.51-37.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-mod_session-2.4.51-37.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.51-37.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-22721', 'CVE-2022-23943', 'CVE-2022-26377', 'CVE-2022-28614', 'CVE-2022-28615', 'CVE-2022-30522', 'CVE-2022-31813']},
      {'reference':'jbcs-httpd24-openssl-1.1.1k-13.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']},
      {'reference':'jbcs-httpd24-openssl-devel-1.1.1k-13.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']},
      {'reference':'jbcs-httpd24-openssl-libs-1.1.1k-13.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']},
      {'reference':'jbcs-httpd24-openssl-perl-1.1.1k-13.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']},
      {'reference':'jbcs-httpd24-openssl-static-1.1.1k-13.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-1292', 'CVE-2022-2068']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jbcs-httpd24-curl / jbcs-httpd24-httpd / jbcs-httpd24-httpd-devel / etc');
}
