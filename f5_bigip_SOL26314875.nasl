#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K26314875.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(177570);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/27");

  script_cve_id("CVE-2022-26377");

  script_name(english:"F5 Networks BIG-IP : Apache vulnerability (K26314875)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 15.1.10.3 / 16.1.4.2 / 17.1.1.1. It is,
therefore, affected by a vulnerability as referenced in the K26314875 advisory.

  - Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of
    Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This
    issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.
    (CVE-2022-26377)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K26314875");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K26314875.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26377");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/23");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K26314875';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
    ],
  },
  'WOM': {
    'affected': [
      '17.0.0-17.1.1','16.1.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.1.1','16.1.4.2','15.1.10.3'
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
