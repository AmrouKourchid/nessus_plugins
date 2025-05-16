#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K52145254.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(137918);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/28");

  script_cve_id("CVE-2020-5902");
  script_xref(name:"IAVA", value:"2020-A-0283-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0122");
  script_xref(name:"CEA-ID", value:"CEA-2020-0055");

  script_name(english:"F5 Networks BIG-IP : TMUI RCE vulnerability (K52145254)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 11.6.5.2 / 12.1.5.2 / 13.1.3.4 / 14.1.2.6 /
15.0.1.4 / 15.1.0.4 / 16.0.0. It is, therefore, affected by a vulnerability as referenced in the K52145254 advisory.

  - In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and
    11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration
    utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages. (CVE-2020-5902)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K52145254");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K52145254.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5902");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"F5 BIG-IP Traffic Management User Interface File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'F5 BIG-IP TMUI Directory Traversal and File Upload RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

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

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K52145254';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'AM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'APM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'ASM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'AVR': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'DNS': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'GTM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'LC': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'LTM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'PEM': {
    'affected': [
      '15.1.0','15.0.0-15.0.1','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
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
