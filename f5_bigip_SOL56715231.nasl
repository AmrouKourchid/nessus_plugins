##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K56715231.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(147623);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2021-22991");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/01");
  script_xref(name:"CEA-ID", value:"CEA-2021-0017");
  script_xref(name:"IAVA", value:"2021-A-0127-S");

  script_name(english:"F5 Networks BIG-IP : TMM buffer-overflow vulnerability (K56715231)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 12.1.5.3 / 13.1.3.6 / 14.1.4 / 15.1.2.1 /
16.0.1.1 / 16.1.0. It is, therefore, affected by a vulnerability as referenced in the K56715231 advisory.

  - On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before
    13.1.3.6, and 12.1.x before 12.1.5.3, undisclosed requests to a virtual server may be incorrectly handled
    by the Traffic Management Microkernel (TMM) URI normalization, which may trigger a buffer overflow,
    resulting in a DoS attack. In certain situations, it may theoretically allow bypass of URL based access
    control or remote code execution (RCE). Note: Software versions which have reached End of Software
    Development (EoSD) are not evaluated. (CVE-2021-22991)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K56715231");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K56715231.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22991");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K56715231';
var vmatrix = {
  'AFM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'AM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'APM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'ASM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'AVR': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'DNS': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'GTM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'LC': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'LTM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
    ],
  },
  'PEM': {
    'affected': [
      '16.0.0-16.0.1','15.1.0-15.1.2','14.1.0-14.1.3','13.1.0-13.1.3','12.1.0-12.1.5'
    ],
    'unaffected': [
      '16.1.0','16.0.1.1','15.1.2.1','14.1.4','13.1.3.6','12.1.5.3'
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
