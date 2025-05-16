#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:3781. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200272);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-5752",
    "CVE-2023-45288",
    "CVE-2023-45290",
    "CVE-2023-49083",
    "CVE-2023-50447",
    "CVE-2024-1135",
    "CVE-2024-3651",
    "CVE-2024-3772",
    "CVE-2024-4340",
    "CVE-2024-21503",
    "CVE-2024-24783",
    "CVE-2024-26130",
    "CVE-2024-27306",
    "CVE-2024-27351",
    "CVE-2024-28219",
    "CVE-2024-28849",
    "CVE-2024-30251",
    "CVE-2024-32879",
    "CVE-2024-34064",
    "CVE-2024-35195"
  );
  script_xref(name:"RHSA", value:"2024:3781");

  script_name(english:"RHEL 8 / 9 : Red Hat Ansible Automation Platform 2.4 Product Security and Bug Fix Update (Moderate) (RHSA-2024:3781)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:3781 advisory.

    Red Hat Ansible Automation Platform provides an enterprise framework for building, deploying and managing
    IT automation at scale. IT Managers can provide top-down guidelines on how automation is applied to
    individual teams, while automation developers retain the freedom to write tasks that leverage existing
    knowledge without the overhead. Ansible Automation Platform makes it possible for users across an
    organization to share, vet, and manage automation content by means of a simple, powerful, and agentless
    language.

    Security Fix(es):

    * automation-controller: aiohttp: DoS when trying to parse malformed POST requests (CVE-2024-30251)
    * automation-controller: Django: Potential regular expression denial-of-service in
    django.utils.text.Truncator.words() (CVE-2024-27351)
    * automation-controller: pip: Mercurial configuration injectable in repo revision when installing via pip
    (CVE-2023-5752)
    * automation-controller: pydantic: regular expression denial of service via crafted email string
    (CVE-2024-3772)
    * automation-hub, python3/python39-galaxy-ng: follow-redirects: Possible credential leak (CVE-2024-28849)
    * python3/python39-aiohttp: DoS when trying to parse malformed POST requests (CVE-2024-30251)
    * python3/python39-aiohttp: XSS on index pages for static file handling (CVE-2024-27306)
    * python3/python39-black: ReDoS via the lines_with_leading_tabs_expanded() function in strings.py file
    (CVE-2024-21503)
    * python3/python39-cryptography: NULL pointer dereference with pkcs12.serialize_key_and_certificates when
    called with a non-matching certificate and private key and an hmac_hash override (CVE-2024-26130)
    * python3/python39-cryptography: NULL-dereference when loading PKCS7 certificates (CVE-2023-49083)
    * python3/python39-cryptography: NULL-dereference when loading PKCS7 certificates (CVE-2023-49083)
    * python3/python39-gunicorn: HTTP Request Smuggling due to improper validation of Transfer-Encoding
    headers (CVE-2024-1135)
    * python3/python39-idna: potential DoS via resource consumption via specially crafted inputs to
    idna.encode() (CVE-2024-3651)
    * python3/python39-jinja2: accepts keys containing non-attribute characters (CVE-2024-34064)
    * python3/python39-pillow: buffer overflow in _imagingcms.c (CVE-2024-28219)
    * python3/python39-pillow: Arbitrary Code Execution via the environment parameter (CVE-2023-50447)
    * python3/python39-pydantic: regular expression denial of service via crafted email string (CVE-2024-3772)
    * python3/python39-requests: subsequent requests to the same host ignore cert verification
    (CVE-2024-35195)
    * python3/python39-social-auth-app-django: Improper Handling of Case Sensitivity in social-auth-app-django
    (CVE-2024-32879)
    * python3/python39-sqlparse: parsing heavily nested list leads to denial of service (CVE-2024-4340)
    * receptor: golang: crypto/x509: Verify panics on certificates with an unknown public key algorithm
    (CVE-2024-24783)
    * receptor: golang: net/http, x/net/http2: unlimited number of CONTINUATION frames causes DoS
    (CVE-2023-45288)
    * receptor: golang: net/http: memory exhaustion in Request.ParseMultipartForm (CVE-2023-45290)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Updates and fixes for automation controller:
    * Fixed Redis connection leak on version 4.5.6 (AAP-24286)
    * automation-controller has been updated to 4.5.7

    Updates and fixes for automation hub:
    * Fixed repository sync issues (AAH-3111, AAH-3218)
    * automation-hub/python3-galaxy-ng/python39-galaxy-ng have been updated to 4.9.2

    Additional changes:
    * ansible-core has been updated to 2.15.11
    * automation-eda-controller has been updated to 1.0.7
    * installer and setup have been updated to 2.4-7
    * receptor has been updated to 1.4.8

    For more details about the updates and fixes included in this release, refer to the Release Notes.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2259479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2279476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282114");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/AAH-3111");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/AAP-22461");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_3781.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83d655b3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:3781");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50447");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-49083");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 77, 79, 80, 120, 200, 303, 400, 444, 476, 670, 674, 835, 1333);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-controller-venv-tower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:automation-hub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-black");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-galaxy-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pydantic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-social-auth-app-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-black");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-galaxy-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pydantic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-social-auth-app-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-black");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-galaxy-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-pydantic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-social-auth-app-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python39-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-black");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-galaxy-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-pydantic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-social-auth-app-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3x-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:receptor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:receptorctl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.2/debug',
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.2/os',
      'content/dist/layered/rhel8/aarch64/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.2/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.2/os',
      'content/dist/layered/rhel8/ppc64le/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.2/debug',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.2/os',
      'content/dist/layered/rhel8/s390x/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.2/debug',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.2/os',
      'content/dist/layered/rhel8/x86_64/ansible-inside/1.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python39-black-22.8.0-2.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-21503']},
      {'reference':'python39-cryptography-42.0.5-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-49083', 'CVE-2024-26130']},
      {'reference':'python39-jinja2-3.1.4-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-34064']},
      {'reference':'receptor-1.4.8-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-45288', 'CVE-2023-45290', 'CVE-2024-24783']},
      {'reference':'receptorctl-1.4.8-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-45288', 'CVE-2023-45290', 'CVE-2024-24783']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/aarch64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/ppc64le/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/s390x/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/os',
      'content/dist/layered/rhel8/x86_64/ansible-developer/1.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-controller-venv-tower-4.5.7-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-5752', 'CVE-2024-3772', 'CVE-2024-27351', 'CVE-2024-30251']},
      {'reference':'python39-idna-3.7-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-3651']},
      {'reference':'python39-requests-2.32.2-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel8/x86_64/ansible-automation-platform/2.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-hub-4.9.2-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-28849']},
      {'reference':'python39-aiohttp-3.9.5-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-27306', 'CVE-2024-30251']},
      {'reference':'python39-galaxy-ng-4.9.2-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-28849']},
      {'reference':'python39-gunicorn-22.0.0-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1135']},
      {'reference':'python39-pillow-10.3.0-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-50447', 'CVE-2024-28219']},
      {'reference':'python39-pydantic-1.10.15-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-3772']},
      {'reference':'python39-social-auth-app-django-5.4.1-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-32879']},
      {'reference':'python39-sqlparse-0.5.0-1.el8ap', 'release':'8', 'el_string':'el8ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-4340']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.2/debug',
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.2/os',
      'content/dist/layered/rhel9/aarch64/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.2/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.2/os',
      'content/dist/layered/rhel9/ppc64le/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.2/debug',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.2/os',
      'content/dist/layered/rhel9/s390x/ansible-inside/1.2/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.2/debug',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.2/os',
      'content/dist/layered/rhel9/x86_64/ansible-inside/1.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python3-black-22.8.0-2.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-21503']},
      {'reference':'python3-cryptography-42.0.5-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-49083', 'CVE-2024-26130']},
      {'reference':'python3-jinja2-3.1.4-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-34064']},
      {'reference':'receptor-1.4.8-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-45288', 'CVE-2023-45290', 'CVE-2024-24783']},
      {'reference':'receptorctl-1.4.8-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-45288', 'CVE-2023-45290', 'CVE-2024-24783']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/aarch64/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/ppc64le/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/s390x/ansible-developer/1.1/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/debug',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/os',
      'content/dist/layered/rhel9/x86_64/ansible-developer/1.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-controller-venv-tower-4.5.7-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-5752', 'CVE-2024-3772', 'CVE-2024-27351', 'CVE-2024-30251']},
      {'reference':'python3-idna-3.7-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-3651']},
      {'reference':'python3-requests-2.32.2-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-35195']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/aarch64/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/ppc64le/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/s390x/ansible-automation-platform/2.4/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/debug',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/os',
      'content/dist/layered/rhel9/x86_64/ansible-automation-platform/2.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'automation-hub-4.9.2-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-28849']},
      {'reference':'python3-aiohttp-3.9.5-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-27306', 'CVE-2024-30251']},
      {'reference':'python3-galaxy-ng-4.9.2-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-28849']},
      {'reference':'python3-gunicorn-22.0.0-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-1135']},
      {'reference':'python3-pillow-10.3.0-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2023-50447', 'CVE-2024-28219']},
      {'reference':'python3-pydantic-1.10.15-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-3772']},
      {'reference':'python3-social-auth-app-django-5.4.1-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-32879']},
      {'reference':'python3-sqlparse-0.5.0-1.el9ap', 'release':'9', 'el_string':'el9ap', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'automation-hub-2.4', 'cves':['CVE-2024-4340']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'automation-controller-venv-tower / automation-hub / python3-aiohttp / etc');
}
