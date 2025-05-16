#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K45353544.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(184248);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/02");

  script_cve_id("CVE-2019-6605");

  script_name(english:"F5 Networks BIG-IP : SSL virtual server vulnerability (K45353544)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 11.5.9 / 11.6.4 / 12.1.0. It is, therefore,
affected by a vulnerability as referenced in the K45353544 advisory.

  - On BIG-IP 11.5.1-11.5.8, 11.6.1-11.6.3, and 12.0.x, an undisclosed sequence of packets received by an SSL
    virtual server and processed by an associated Client SSL or Server SSL profile may cause a denial of
    service. (CVE-2019-6605)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K45353544");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K45353544.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6605");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/02");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

var sol = 'K45353544';
var vmatrix = {
  'AFM': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'AM': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'APM': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'ASM': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'AVR': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'DNS': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'GTM': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'LC': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'LTM': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'PEM': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
    ],
  },
  'WAM': {
    'affected': [
      '12.0.0','11.6.0-11.6.3','11.5.0-11.5.8'
    ],
    'unaffected': [
      '12.1.0','11.6.4','11.5.9'
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
