#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K34303485.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(184240);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2019-11091");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"F5 Networks BIG-IP : Microarchitectural Data Sampling Uncacheable Memory (MDSUM) (K34303485)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K34303485 advisory.

  - Microarchitectural Data Sampling Uncacheable Memory (MDSUM): Uncacheable memory on some microprocessors
    utilizing speculative execution may allow an authenticated user to potentially enable information
    disclosure via a side channel with local access. A list of impacted products can be found here:
    https://www.intel.com/content/dam/www/public/us/en/documents/corporate-information/SA00233-microcode-
    update-guidance_05132019.pdf (CVE-2019-11091)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K34303485");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11091");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
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

var sol = 'K34303485';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.0.0','14.0.0-14.1.0','13.0.0-13.1.1','12.0.0-12.1.4','11.6.0-11.6.4'
    ],
  },
  'AM': {
    'affected': [
      '15.0.0','14.0.0-14.1.0','13.0.0-13.1.1','12.0.0-12.1.4','11.6.0-11.6.4'
    ],
  },
  'APM': {
    'affected': [
      '15.0.0','14.0.0-14.1.0','13.0.0-13.1.1','12.0.0-12.1.4','11.6.0-11.6.4'
    ],
  },
  'ASM': {
    'affected': [
      '15.0.0','14.0.0-14.1.0','13.0.0-13.1.1','12.0.0-12.1.4','11.6.0-11.6.4'
    ],
  },
  'AVR': {
    'affected': [
      '15.0.0','14.0.0-14.1.0','13.0.0-13.1.1','12.0.0-12.1.4','11.6.0-11.6.4'
    ],
  },
  'DNS': {
    'affected': [
      '15.0.0','14.0.0-14.1.0','13.0.0-13.1.1','12.0.0-12.1.4','11.6.0-11.6.4'
    ],
  },
  'GTM': {
    'affected': [
      '15.0.0','14.0.0-14.1.0','13.0.0-13.1.1','12.0.0-12.1.4','11.6.0-11.6.4'
    ],
  },
  'LTM': {
    'affected': [
      '15.0.0','14.0.0-14.1.0','13.0.0-13.1.1','12.0.0-12.1.4','11.6.0-11.6.4'
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
