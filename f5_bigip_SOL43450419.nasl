#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K43450419.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(136137);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2020-5871");
  script_xref(name:"IAVA", value:"2021-A-0108-S");

  script_name(english:"F5 Networks BIG-IP : TMM vulnerability (K43450419)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Undisclosed requests can lead to a denial of service (DoS) when sent
to BIG-IP HTTP/2 virtual servers. The problem can occur when ciphers,
which have been blacklisted by the HTTP/2 RFC, are used on backend
servers. This is a data-plane issue. There is no control-plane
exposure. (CVE-2020-5871)

Impact

This vulnerability affects only the virtual server associated with the
HTTP/2 profile that has the HTTP MRF Router setting selected. The
BIG-IP system may temporarily fail to process traffic as it recovers
from a Traffic Management Microkernel (TMM) restart. If the BIG-IP
system is configured for high availability (HA), it fails over to a
peer system.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K43450419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K43450419.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5871");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K43450419';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'AM': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'APM': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'ASM': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'AVR': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'DNS': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'GTM': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'LC': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'LTM': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
    ],
  },
  'PEM': {
    'affected': [
      '14.1.0-14.1.2'
    ],
    'unaffected': [
      '15.0.0','14.1.2.4'
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
