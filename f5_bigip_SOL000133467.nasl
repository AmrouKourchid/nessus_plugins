#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000133467.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(183047);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2023-40534");
  script_xref(name:"IAVA", value:"2023-A-0537-S");

  script_name(english:"F5 Networks BIG-IP HTTP/2 DoS (K000133467)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 17.1.0.3 / 16.1.4.1.
It is, therefore, affected by a vulnerability as referenced in the K000133467 advisory.
Undisclosed requests can cause the Traffic Management Microkernel (TMM) to terminate when a client-side
HTTP/2 profile and the HTTP MRF Router option are enabled for a virtual server and an iRule using the 
HTTP_REQUEST event or Local Traffic Policy are associated with the virtual server. TMM can also terminate
when a client-side HTTP/2 profile and the HTTP MRF Router option are enabled, regardless of the presence 
of the iRule. 

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K000133467");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000133467.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40534");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

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
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K000133467';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  },
  'APM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  },
  'ASM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  },
  'GTM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  },
  'PSM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  },
  'WOM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.4'
    ],
    'unaffected': [
      '17.1.0.3.0.23.4','17.1.1.0.2.6', '16.1.4.1.0.13.5'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
