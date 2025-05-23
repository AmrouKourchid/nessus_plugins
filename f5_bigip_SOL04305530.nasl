#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K04305530.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(179676);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/25");

  script_cve_id("CVE-2020-15778");

  script_name(english:"F5 Networks BIG-IP : SCP vulnerability (K04305530)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K04305530 advisory.

    scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by
    backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they
    intentionally omit validation of anomalous argument transfers because that could stand a great chance
    of breaking existing workflows.(CVE-2020-15778)ImpactThis flaw is found in the SCP program shipped with
    theopenssh-clientspackage. An attacker having the ability to SCP files to a remote server could run
    arbitrary commands on the remote server by including a command as a part of the filename being copied on
    the server. This command runs with the user permissions used to copy the files on the remote server. The
    most serious threats from this vulnerability are to data confidentiality and integrity, as well as to
    system availability.

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K04305530");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/11");

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

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K04305530';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'APM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'ASM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'GTM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'PSM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'SSL-Orchestrator': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'WOM': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'iAppsLX': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'iRulesLX': {
    'affected': [
      '17.1.0-17.1.1','16.1.0-16.1.5','15.1.0-15.1.10','14.1.0-14.1.5','13.1.0-13.1.5','12.1.0-12.1.6','11.6.1-11.6.5'
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
