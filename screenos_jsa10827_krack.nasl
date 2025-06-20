#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105654);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081"
  );
  script_bugtraq_id(101274);
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"Juniper ScreenOS 6.3 SSG-5 and SSG-20 (KRACK)");
  script_summary(english:"Checks ScreenOS version");

  script_set_attribute(attribute:"synopsis", value:
"The device is vulnerable to key reinstallation attacks (KRACK).");
  script_set_attribute(attribute:"description", value:
"The version of Juniper ScreenOS installed on the remote host
is affected by multiple vulnerabilities related to the KRACK attacks.
This may allow an attacker to decrypt, replay, and forge some frames
on a WPA2 encrypted network.

Note that Juniper's products do not support Fast BSS Transition
Reassociation and PeerKey Handshake so are Not Vulnerable to
CVE-2017-13082, CVE-2017-13084, CVE-2017-13086, CVE-2017-13087,
or CVE-2017-13088.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10827&pmv=print&actp=RSS&searchid=&type=currentpaging
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a379f4f4");
  script_set_attribute(attribute:"solution", value:
"Disable all Wi-Fi configurations and refer to the vendor
advisory for further solution and mitigation options.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13077");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/Version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/ScreenOS/Version');
port = 0;

if (ver =~ "^6\.3")
{
    report =
    '\n  Installed version : '+ver+
    '\n  Fixed version     : '+ "N/A. Refer to Vendor for mitigation options." +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else
  audit(AUDIT_HOST_NOT, "affected");

