##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K83120834.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(161373);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2002-20001", "CVE-2022-40735");

  script_name(english:"F5 Networks BIG-IP : Diffie-Hellman key agreement protocol weaknesses (K83120834)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to 16.1.4 / 17.1.0. It is, therefore, affected
by multiple vulnerabilities as referenced in the K83120834 advisory.

    The Diffie-Hellman Key Agreement Protocol allows remote attackers (from the client side) to send arbitrary
    numbers that are actually not public keys, and trigger expensive server-side DHE modular-exponentiation
    calculations, aka a D(HE)ater attack. The client needs very little CPU resources and network bandwidth.
    The attack may be more disruptive in cases where a client can require a server to select its largest
    supported key size. The basic attack scenario is that the client must claim that it can only communicate
    with DHE, and the server must be configured to allow DHE.(CVE-2002-20001)The Diffie-Hellman Key Agreement
    Protocol allows use of long exponents that arguably make certain calculations unnecessarily expensive,
    because the 1996 van Oorschot and Wiener paper found that (appropriately) short exponents can be used
    when there are adequate subgroup constraints, and these short exponents can lead to less expensive
    calculations than for long exponents. This issue is different from CVE-2002-20001 because it is based on
    an observation about exponent size, rather than an observation about numbers that are not public keys. The
    specific situations in which calculation expense would constitute a server-side vulnerability depend on
    the protocol (e.g., TLS, SSH, or IKE) and the DHE implementation details. In general, there might be an
    availability concern because of server-side resource consumption from DHE modular-exponentiation
    calculations. Finally, it is possible for an attacker to exploit this vulnerability and CVE-2002-20001
    together. (CVE-2022-40735)

Tenable has extracted the preceding description block directly from the F5 Networks BIG-IP security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K83120834");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K83120834.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-20001");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-40735");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/19");

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

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var sol = 'K83120834';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0-17.1.0','17.0.0','16.1.0-16.1.4','16.1.0-16.1.3','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
    'unaffected': [
      '17.1.0','16.1.4'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'SSL-Orchestrator': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'WOM': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'iAppsLX': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'iRulesLX': {
    'affected': [
      '17.0.0-17.1.0','16.1.0-16.1.4','15.1.0-15.1.9','14.1.0-14.1.5','13.1.0-13.1.5'
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
