#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000137322.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(188001);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/01");
  script_xref(name:"IAVA", value:"2024-A-0005-S");

  script_name(english:"F5 Networks BIG-IP : HTTP redirect vulnerability (K000137322)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 15.1.10.3 / 16.1.4.2 / 17.1.1.1. It is,
therefore, affected by a vulnerability as referenced in the K000137322 advisory.

  - A specifically crafted HTTP request may lead the BIG-IP system to generate multiple HTTP redirect responses.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000137322");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000137322.");
  script_set_attribute(attribute:"workaround_type", value:"config_change");
  script_set_attribute(attribute:"workaround", value:
"F5 lists a workaround with instructions listed at https://my.f5.com/manage/s/article/K000137322 that can be achieved using
the following steps:

  1. Following the instructions in the advisory, create the appropriate mitigation iRule for the virtual server.

Note that Tenable always advises that you upgrade a system if possible, 
and all steps listed here are mitigation steps provided by F5. 
Tenable is not responsible for any negative effects that may occur from enacting this workaround.");
  script_set_attribute(attribute:"workaround_publication_date", value:"2023/10/26");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on vendor advisory");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K000137322';
var vmatrix = {
  'AFM': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
    ],
  },
  'APM': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
    ],
  },
  'ASM': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
    ],
  },
  'DNS': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
    ],
  },
  'GTM': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
    ],
  },
  'LTM': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
    ],
  },
  'PEM': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
    ],
  },
  'PSM': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
    ],
  },
  'WOM': {
    'affected': [
      '13.1.0-13.1.5','14.1.0-14.1.5', '15.1.0-15.1.10', '16.1.0-16.1.4', '17.1.0-17.1.1'
    ],
    'unaffected': [
      '15.1.10.3','16.1.4.2','17.1.1.1'
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
