#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K43310520.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(142248);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2020-5940");
  script_xref(name:"IAVA", value:"2020-A-0395-S");

  script_name(english:"F5 Networks BIG-IP : BIG-IP TMUI vulnerability (K43310520)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A stored cross-site scripting (XSS) vulnerability exists in an
undisclosed page of the BIG-IP Traffic Management User Interface
(TMUI), also known as the BIG-IP Configuration utility.
(CVE-2020-5940)

Impact

An authenticated attacker may be able to store JavaScript, whichis
executed when another authenticated user accesses the Configuration
utility. If the victim is an administrator user with AdvancedShell(
bash ) access, an attacker can use Remote Code Execution to leverage a
successful exploitof this vulnerability into a complete compromise of
the BIG-IP system. All authenticated users can store this attack,
regardless of role.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K43310520");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K43310520.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5940");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
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

var sol = 'K43310520';
var vmatrix = {
  'AFM': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'AM': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'APM': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'ASM': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'AVR': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'DNS': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'GTM': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'LC': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'LTM': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'PEM': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  },
  'WAM': {
    'affected': [
      '16.0.0','15.1.0','14.1.0-14.1.2'
    ],
    'unaffected': [
      '16.1.0','16.0.1','15.1.1','14.1.2.4'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
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
