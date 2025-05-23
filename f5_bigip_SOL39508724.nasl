#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K39508724.
#
# The text description of this plugin is (C) F5 Networks.
#

include('compat.inc');

if (description)
{
  script_id(93749);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id("CVE-2016-6907");

  script_name(english:"F5 Networks BIG-IP : TMM SSL/TLS virtual server vulnerability (K39508724)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"TMM SSL/TLS virtual server using CBC cipher may be vulnerable to a
'Vaudenay timing attack' aka 'Padding oracle attack.'(CVE-2016-6907)

The BIG-IP system may be vulnerable to a padding oracle attack on the
following platforms :

The VIPRION B4450 blade and BIG-IP 2000 and 4000 series platforms are
vulnerable with any CBC cipher (not AES-GCM or RC4).

BIG-IP Virtual Edition (VE) and cloud (not vCMP) are vulnerable with
any CBC cipher (not AES-GCM or RC4).

All other hardware platforms with the Cavium Nitrox card that
negotiate the Camellia cipher are vulnerable. Note : The Camellia
cipher was introduced in BIG-IP 12.0.0 and is always processed in
software.

Note : BIG-IP platforms that use the Cavium Nitrox card can become
vulnerable if hardware crypto is disabled, as software crypto will not
use the Cavium Nitrox card.For example, a Common Criteria deployment
will disable the Cavium Nitrox card and introduce this vulnerability.

Note : All ciphers supported by the BIG-IP system, other than AES-GCM
and RC4, are CBC mode ciphers,even if the cipher name does not
explicitly containthe word CBC.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K39508724");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K39508724.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K39508724";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("12.1.0HF1","12.1.0","12.0.0HF1-12.0.0HF3","11.6.1-12.0.0","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10");
vmatrix["AFM"]["unaffected"] = make_list("12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("12.1.0HF1","12.1.0","12.0.0HF1-12.0.0HF3","11.6.1-12.0.0","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10");
vmatrix["AM"]["unaffected"] = make_list("12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("12.1.0HF1","12.1.0","12.0.0HF1-12.0.0HF3","11.6.1-12.0.0","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10","11.2.1HF13-11.2.1HF15","10.2.4HF10-10.2.4HF13");
vmatrix["APM"]["unaffected"] = make_list("12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("12.1.0HF1","12.1.0","12.0.0HF1-12.0.0HF3","11.6.1-12.0.0","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10","11.2.1HF13-11.2.1HF15","10.2.4HF10-10.2.4HF13");
vmatrix["ASM"]["unaffected"] = make_list("12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("12.1.0HF1","12.1.0","12.0.0HF1-12.0.0HF3","11.6.1-12.0.0","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10","11.2.1HF13-11.2.1HF15");
vmatrix["AVR"]["unaffected"] = make_list("12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.6.1","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10","11.2.1HF13-11.2.1HF15","10.2.4HF10-10.2.4HF13");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("12.1.0HF1","12.1.0","12.0.0HF1-12.0.0HF3","11.6.1-12.0.0","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10","11.2.1HF13-11.2.1HF15","10.2.4HF10-10.2.4HF13");
vmatrix["LC"]["unaffected"] = make_list("12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("12.1.0HF1","12.1.0","12.0.0HF1-12.0.0HF3","11.6.1-12.0.0","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10","11.2.1HF13-11.2.1HF15","10.2.4HF10-10.2.4HF13");
vmatrix["LTM"]["unaffected"] = make_list("12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("12.1.0HF1","12.1.0","12.0.0HF1-12.0.0HF3","11.6.1-12.0.0","11.6.0HF1-11.6.0HF7","11.6.0","11.5.4HF1","11.5.2-11.5.4","11.5.1HF6-11.5.1HF10","11.5.0HF6-11.5.0HF7","11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10");
vmatrix["PEM"]["unaffected"] = make_list("12.1.1","12.1.0HF2","12.0.0HF4","11.6.1HF1","11.6.0HF8","11.5.4HF2","11.5.1HF11","11.4.1HF11","11.2.1HF16");

# PSM
vmatrix["PSM"] = make_array();
vmatrix["PSM"]["affected"  ] = make_list("11.4.1HF6-11.4.1HF10","11.4.0HF9-11.4.0HF10","11.2.1HF13-11.2.1HF15","10.2.4HF10-10.2.4HF13");
vmatrix["PSM"]["unaffected"] = make_list("11.4.1HF11","11.2.1HF16");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("11.2.1HF13-11.2.1HF15","10.2.4HF10-10.2.4HF13");
vmatrix["WAM"]["unaffected"] = make_list("11.2.1HF16");

# WOM
vmatrix["WOM"] = make_array();
vmatrix["WOM"]["affected"  ] = make_list("11.2.1HF13-11.2.1HF15","10.2.4HF10-10.2.4HF13");
vmatrix["WOM"]["unaffected"] = make_list("11.2.1HF16");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
