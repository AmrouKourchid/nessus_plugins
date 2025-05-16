#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K97810133.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(137378);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/07");

  script_cve_id("CVE-2020-8616");

  script_name(english:"F5 Networks BIG-IP : BIND vulnerability (K97810133)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A malicious actor who intentionally exploits this lack of effective
limitation on the number of fetches performed when processing
referrals can, through the use of specially crafted referrals, cause a
recursing server to issue a very large number of fetches in an attempt
to process the referral. This has at least two potential effects: The
performance of the recursing server can potentially be degraded by the
additional work required to perform these fetches, and the attacker
can exploit this behavior to use the recursing server as a reflector
in a reflection attack with a high amplification
factor.(CVE-2020-8616)

For more information, refer toISC Security Advisory CVE-2020-8616 and
the academic paper, NXNSAttack, prepared by the discoverers and
reporters of this vulnerability.

Note : These links takeyou to resources outside of AskF5, and it is
possible that the documents may be removed without our knowledge.

Impact

This vulnerability has at least two potential effects: the performance
of the recursing server can potentially be degraded by the additional
work required to perform these fetches, and the attacker can exploit
this behavior to use the recursing server as a reflector in a
reflection attack with a high amplification factor.

An attacker could exploit this vulnerability to generate a large
number of communications between the BIG-IP system and the victim's
authoritative DNS server to cause a distributed denial-of-service
(DDoS) attack.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K97810133");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K97810133.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var sol = 'K97810133';
var vmatrix = {
  'AFM': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'AM': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'APM': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'ASM': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'AVR': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
    ],
    'unaffected': [
      '16.0.0','15.1.0.4','15.0.1.4','14.1.2.6','13.1.3.4','12.1.5.2','11.6.5.2'
    ],
  },
  'LTM': {
    'affected': [
      '15.0.0-15.1.0','14.1.0-14.1.2','13.1.0-13.1.3','12.1.0-12.1.5','11.6.1-11.6.5'
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
