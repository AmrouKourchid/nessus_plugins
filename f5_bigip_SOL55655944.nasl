#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K55655944.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(184246);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id("CVE-2019-6675");

  script_name(english:"F5 Networks BIG-IP : BIG-IP Engineering Hotfix authentication bypass vulnerability (K55655944)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K55655944 advisory.

  - BIG-IP configurations using Active Directory, LDAP, or Client Certificate LDAP for management
    authentication with multiple servers are exposed to a vulnerability which allows an authentication bypass.
    This can result in a complete compromise of the system. This issue only impacts specific engineering
    hotfixes using the aforementioned authentication configuration. NOTE: This vulnerability does not affect
    any of the BIG-IP major, minor or maintenance releases you obtained from downloads.f5.com. The affected
    Engineering Hotfix builds are as follows: Hotfix-BIGIP-14.1.0.3.0.79.6-ENG.iso, Hotfix-
    BIGIP-14.1.0.3.0.97.6-ENG.iso, Hotfix-BIGIP-14.1.0.3.0.99.6-ENG.iso, Hotfix-BIGIP-14.1.0.5.0.15.5-ENG.iso,
    Hotfix-BIGIP-14.1.0.5.0.36.5-ENG.iso, Hotfix-BIGIP-14.1.0.5.0.40.5-ENG.iso, Hotfix-
    BIGIP-14.1.0.6.0.11.9-ENG.iso, Hotfix-BIGIP-14.1.0.6.0.14.9-ENG.iso, Hotfix-BIGIP-14.1.0.6.0.68.9-ENG.iso,
    Hotfix-BIGIP-14.1.0.6.0.70.9-ENG.iso, Hotfix-BIGIP-14.1.2.0.11.37-ENG.iso, Hotfix-
    BIGIP-14.1.2.0.18.37-ENG.iso, Hotfix-BIGIP-14.1.2.0.32.37-ENG.iso, Hotfix-BIGIP-14.1.2.1.0.46.4-ENG.iso,
    Hotfix-BIGIP-14.1.2.1.0.14.4-ENG.iso, Hotfix-BIGIP-14.1.2.1.0.16.4-ENG.iso, Hotfix-
    BIGIP-14.1.2.1.0.34.4-ENG.iso, Hotfix-BIGIP-14.1.2.1.0.97.4-ENG.iso, Hotfix-BIGIP-14.1.2.1.0.99.4-ENG.iso,
    Hotfix-BIGIP-14.1.2.1.0.105.4-ENG.iso, Hotfix-BIGIP-14.1.2.1.0.111.4-ENG.iso, Hotfix-
    BIGIP-14.1.2.1.0.115.4-ENG.iso, Hotfix-BIGIP-14.1.2.1.0.122.4-ENG.iso, Hotfix-
    BIGIP-15.0.1.0.33.11-ENG.iso, Hotfix-BIGIP-15.0.1.0.48.11-ENG.iso (CVE-2019-6675)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K55655944");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6675");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

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

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K55655944';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
  },
  'AM': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
  },
  'APM': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
  },
  'ASM': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
  },
  'AVR': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
  },
  'DNS': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
   'unaffected' : [ '15.1', '16' , '17'],
  },
  'GTM': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
  },
  'LC': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
  },
  'LTM': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
  },
  'PEM': {
    'affected': [
      '15.0.1.0.48.11-ENG Hotfix','15.0.1.0.33.11-ENGÂ Hotfix','14.1.2.1.0.99.4-ENG Hotfix','14.1.2.1.0.97.4-ENG Hotfix','14.1.2.1.0.46.4-ENG Hotfix','14.1.2.1.0.34.4-ENG Hotfix','14.1.2.1.0.16.4-ENG Hotfix','14.1.2.1.0.14.4-ENG Hotfix','14.1.2.1.0.122.4-ENG Hotfix','14.1.2.1.0.115.4-ENG Hotfix','14.1.2.1.0.111.4-ENG Hotfix','14.1.2.1.0.105.4-ENG Hotfix','14.1.2.0.32.37-ENG Hotfix','14.1.2.0.18.37-ENG Hotfix','14.1.2.0.11.37-ENG Hotfix','14.1.0.6.0.70.9-ENG Hotfix','14.1.0.6.0.68.9-ENG Hotfix','14.1.0.6.0.14.9-ENG Hotfix','14.1.0.6.0.11.9-ENG Hotfix','14.1.0.5.0.40.5-ENG Hotfix','14.1.0.5.0.36.5-ENG Hotfix','14.1.0.5.0.15.5-ENG Hotfix','14.1.0.3.0.99.6-ENG Hotfix','14.1.0.3.0.97.6-ENG Hotfix','14.1.0.3.0.79.6-ENG Hotfix'
    ],
    'unaffected' : [ '15.1', '16' , '17'],
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

