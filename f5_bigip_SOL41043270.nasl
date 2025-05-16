#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K41043270.
#
# @NOAGENT@
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154689);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id("CVE-2021-0086", "CVE-2021-0089");

  script_name(english:"F5 Networks BIG-IP : Intel processor vulnerabilities (K41043270)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the K41043270 advisory.

    CVE-2021-0086Observable response discrepancy in floating-point operations for some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local
    access.CVE-2021-0089Observable response discrepancy in some Intel(R) Processors may allow an authorized
    user to potentially enable information disclosure via local access.ImpactAll versions of Virtual Edition
    (VE) for the BIG-IP and BIG-IQ products are potentially impacted if the processors underlying the VE
    installations areaffected. Microcode updates from Intel are available to address this issue but must be
    applied at the hardware level, which is outside the scope of the ability of F5 to support or patch.This
    hardware issue impacts all the BIG-IP, BIG-IQ, VIPRION, and VELOS platforms using the following Intel Xeon
    processor families:Ivy Bridge EPSandy Bridge EPIvy BridgeSandy BridgeHanswell EBroadwellSkylake-DThe
    following BIG-IP, BIG-IQ, VIPRION, and VELOS platforms are vulnerable:A112 VIPRION Blade 2250A114VIPRION
    Blade 4450A118 VELOS Blade BX110C109 BIG-IP 5000s, 5200v, 5050s, 5250v, 5250v-FC115BIG-IP iSeries i4600,
    i4800C116 BIG-IP iSeries i10600, i10600-D, i10800, i10800-DC117BIG-IP iSeries i850, i2600,
    i2800C118BIG-IP iSeries i7600, i7600-D, i7800, i7800-DC119BIG-IP iSeries i5600, i5800C123BIG-IP
    iSeries i11600, i11800C124BIG-IP iSeries i11400-DS,i11600-DS,i11800-DSC125BIG-IP iSeries
    i5820-DFC126BIG-IP iSeries i7820-DFD110 BIG-IP 7000s, 7200v, 7200s-SSL, 7200v-FIPS, 7050s, 7250v, 7055s,
    7255sD110 BIG-IQ 7000D111 BIG-IP 12250vD112 BIG-IP 10350v, 10150s-N, 10350v-N, 10350v-FD113 BIG-IP 10000s,
    10200v, 10200v-SSL, 10200v-FIPS, 10050s, 10250v, 10055s, 10255vD116 BIG-IP iSeries i15600, i15800E102 BIG-
    IP 11050 NEBSThe following BIG-IP and VIPRION platforms are not vulnerable:A107VIPRION Blade 4200A108
    VIPRION Blade 4300A109VIPRION Blade 2100A110VIPRION Blade 4340A111VIPRION Blade 4200NA113VIPRION
    Blade 2150C102 BIG-IP 1600, 1600 LCC103 BIG-IP 3600C106BIG-IP 3900C112 BIG-IP 2000s, 2200sC113 BIG-IP
    4000s, 4200vC114 BIG-IP 800D104 BIG-IP 6900, 6900s, 6900 FIPSD106 BIG-IP 8900, 8900 FIPSD107 BIG-IP 8950,
    8950sE101 BIG-IP 11000, 11000 FIPSE102 BIG-IP 11050 FIPSE102 BIG-IP 11050

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K41043270");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_iapps_lx");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_irules_lx");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_ssl_orchestrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Settings/ParanoidReport", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var sol = 'K41043270';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'APM': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'ASM': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'GTM': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'PSM': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'SSL-Orchestrator': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'WOM': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'iAppsLX': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'iRulesLX': {
    'affected': [
      '17.1.0-17.1.1','16.0.0-16.1.4','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
