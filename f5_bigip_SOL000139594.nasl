#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K000139594.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(197038);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/24");

  script_cve_id("CVE-2022-40304");

  script_name(english:"F5 Networks BIG-IP : libxml2 vulnerability (K000139594)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 17.1.2.2 / 17.5.0. It is, therefore, affected
by a vulnerability as referenced in the K000139594 advisory.

    An issue was discovered in libxml2 before 2.10.3. Certain invalid XML entity definitions can corrupt a
    hash table key, potentially leading to subsequent logic errors. In one case, a double-free can be
    provoked.(CVE-2022-40304).

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K000139594");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K000139594.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40304");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
    script_set_attribute(attribute:"workaround_type", value:"config_change");
    script_set_attribute(attribute:"workaround", value:"F5 lists a workaround with instructions listed at https://my.f5.com/manage/s/article/K000139594 that can be achieved using
the following steps:

    1. XML data does not comply with format settings
    2. Disable Document Type Definition (DTD) reference declaration 
    3. Do not permit DTD declaration in monitors 
    4. Do not permit iRules that contain custom XML.

Note that Tenable always advises that you upgrade a system if possible, 
and all steps listed here are mitigation steps provided by F5. 
Tenable is not responsible for any negative effects that may occur from enacting this workaround.");
    script_set_attribute(attribute:"workaround_publication_date", value:"2022/10/20");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
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

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K000139594';
var vmatrix = {
  'AM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.4','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2'
    ],
  },
  'AVR': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.4','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2'
    ],
  },
  'DNS': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.4','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2'
    ],
  },
  'LC': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.4','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2'
    ],
  },
  'LTM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.4','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2'
    ],
  },
  'PEM': {
    'affected': [
      '17.1.0-17.1.2','16.1.0-16.1.4','15.1.0-15.1.10'
    ],
    'unaffected': [
      '17.5.0','17.1.2.2'
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
