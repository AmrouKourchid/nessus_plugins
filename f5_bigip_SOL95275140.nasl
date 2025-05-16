#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K95275140.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(125485);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2018-3620");

  script_name(english:"F5 Networks BIG-IP : OS Kernel and SMM mode L1 Terminal Fault vulnerability (K95275140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 14.1.2.2 / 15.0.0. It is, therefore, affected
by a vulnerability as referenced in the K95275140 advisory.

  - Systems with microprocessors utilizing speculative execution and address translations may allow
    unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access
    via a terminal page fault and a side-channel analysis. (CVE-2018-3620)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K95275140");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K95275140.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3620");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K95275140';
var vmatrix = {
  'AFM': {
    'affected': [
      '14.0.0-14.1.2','13.0.0-13.1.1','12.1.0-12.1.3','11.2.1-11.6.3'
    ],
    'unaffected': [
      '15.0.0','14.1.2.2'
    ],
  },
  'AM': {
    'affected': [
      '14.0.0-14.1.2','13.0.0-13.1.1','12.1.0-12.1.3','11.2.1-11.6.3'
    ],
    'unaffected': [
      '15.0.0','14.1.2.2'
    ],
  },
  'APM': {
    'affected': [
      '14.0.0-14.1.2','13.0.0-13.1.1','12.1.0-12.1.3','11.2.1-11.6.3'
    ],
    'unaffected': [
      '15.0.0','14.1.2.2'
    ],
  },
  'ASM': {
    'affected': [
      '14.0.0-14.1.2','13.0.0-13.1.1','12.1.0-12.1.3','11.2.1-11.6.3'
    ],
    'unaffected': [
      '15.0.0','14.1.2.2'
    ],
  },
  'AVR': {
    'affected': [
      '14.0.0-14.1.2','13.0.0-13.1.1','12.1.0-12.1.3','11.2.1-11.6.3'
    ],
    'unaffected': [
      '15.0.0','14.1.2.2'
    ],
  },
  'DNS': {
    'affected': [
      '14.0.0-14.1.2','13.0.0-13.1.1','12.1.0-12.1.3','11.2.1-11.6.3'
    ],
    'unaffected': [
      '15.0.0','14.1.2.2'
    ],
  },
  'GTM': {
    'affected': [
      '14.0.0-14.1.2','13.0.0-13.1.1','12.1.0-12.1.3','11.2.1-11.6.3'
    ],
    'unaffected': [
      '15.0.0','14.1.2.2'
    ],
  },
  'LTM': {
    'affected': [
      '14.0.0-14.1.2','13.0.0-13.1.1','12.1.0-12.1.3','11.2.1-11.6.3'
    ],
    'unaffected': [
      '15.0.0','14.1.2.2'
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
