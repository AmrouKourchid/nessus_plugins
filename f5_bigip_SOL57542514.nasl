#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K57542514.
#
# The text description of this plugin is (C) F5 Networks.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151496);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id("CVE-2019-10160", "CVE-2019-9636");

  script_name(english:"F5 Networks BIG-IP : Python vulnerabilities (K57542514)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 16.1.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the K57542514 advisory.

    Python 2.7.x through 2.7.16 and 3.x through 3.7.2 is affected by: Improper Handling of Unicode Encoding
    (with an incorrect netloc) during NFKC normalization. The impact is: Information disclosure (credentials,
    cookies, etc. that are cached against a given hostname). The components are: urllib.parse.urlsplit,
    urllib.parse.urlparse. The attack vector is: A specially crafted URL could be incorrectly parsed to locate
    cookies or authentication data and send that information to a different host than when parsed correctly.
    This is fixed in: v2.7.17, v2.7.17rc1, v2.7.18, v2.7.18rc1; v3.5.10, v3.5.10rc1, v3.5.7, v3.5.8,
    v3.5.8rc1, v3.5.8rc2, v3.5.9; v3.6.10, v3.6.10rc1, v3.6.11, v3.6.11rc1, v3.6.12, v3.6.9, v3.6.9rc1;
    v3.7.3, v3.7.3rc1, v3.7.4, v3.7.4rc1, v3.7.4rc2, v3.7.5, v3.7.5rc1, v3.7.6, v3.7.6rc1, v3.7.7, v3.7.7rc1,
    v3.7.8, v3.7.8rc1, v3.7.9.(CVE-2019-9636)A security regression of CVE-2019-9636 was discovered in python
    since commit d537ab0ff9767ef024f26246899728f0116b1ec3 affecting versions 2.7, 3.5, 3.6, 3.7 and from
    v3.8.0a4 through v3.8.0b1, which still allows an attacker to exploit CVE-2019-9636 by abusing the user and
    password parts of a URL. When an application parses user-supplied URLs to store cookies, authentication
    credentials, or other kind of information, it is possible for an attacker to provide specially crafted
    URLs to make the application locate host-related information (e.g. cookies, authentication data) and send
    them to a different host than where it should, unlike if the URLs had been correctly parsed. The result of
    an attack may vary based on the application.(CVE-2019-10160)ImpactA remote attacker may be able to use a
    specially crafted URL to locate cookies or authentication data and send that information to a different
    host than when parsed correctly.BIG-IP Extended Application Verification (EAV) monitors using the
    Pythonurlsplit()function with URLs from an untrusted source may be impacted by this vulnerability.

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K57542514");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K57542514.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9636");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var sol = 'K57542514';
var vmatrix = {
  'AFM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'AM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'APM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'ASM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'AVR': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'DNS': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'GTM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'LC': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'LTM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  },
  'PEM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.1.0'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
}
else
{
  var tested = bigip_get_tested_modules();
  var audit_extra = 'For BIG-IP module(s) ' + tested + ',';
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, 'running any of the affected modules');
}
