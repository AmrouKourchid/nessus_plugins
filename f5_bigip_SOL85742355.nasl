#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K85742355.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(184297);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/07");

  script_cve_id("CVE-2020-14577");

  script_name(english:"F5 Networks BIG-IP : Java SE vulnerability (K85742355)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
a vulnerability as referenced in the K85742355 advisory.

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JSSE). Supported
    versions that are affected are Java SE: 7u261, 8u251, 11.0.7 and 14.0.1; Java SE Embedded: 8u251.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via TLS to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2020-14577)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K85742355");
  script_set_attribute(attribute:"solution", value:
"The vendor has acknowledged the vulnerability, but no solution has been provided.
Refer to the vendor for remediation guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/03");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var sol = 'K85742355';
var vmatrix = {
  'AFM': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'APM': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'ASM': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'DNS': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'GTM': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'LTM': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'PEM': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'PSM': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
    ],
  },
  'WOM': {
    'affected': [
      '16.1.0-16.1.2','16.0.0-16.0.1','15.1.0-15.1.5','14.1.0-14.1.4','13.1.0-13.1.4','12.1.0-12.1.6','11.6.1-11.6.5'
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
