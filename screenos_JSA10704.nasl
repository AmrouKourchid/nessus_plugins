#TRUSTED b2639a777b44f1618300d1341ab2278750c7967f0534aecbe8b41fc112a21b6b67841ef225d04c208d300b8dc5fe37c38d1587bc3a02d33b8312ee549692a7fddbb7a634145d16b35506fcbd64028d2df2527d24a4e9b1e6251f3c9169152264c8dc7980b57136729b0ccec201aae7bfb887975eae93741c466719bd608be4c75863f2e19913c5d722b1e1b16ecdb2d3387094a798f566eb9cda826f7ad77df33c650ac66674b8d6ef970b771d674969f3f5ea83c644403960f51b2c9f95d3398a80eb632bdfedbfe9fb6de80a1e7b7c75e8a7ddba30aaab4c289b2937351db4bd3ea77be700bedcbe71d9a3d41c924c20a691d13f574b6d1073f56a5619e9d85f06f7b49d6102b80a455b72d0b39e29cf3164bf3e2dfb9212590be45b1b488cb0fdd3ac96939013344b9ed4290ae5304adf1cae7ffb96696a198355fe770cb055427ba631b1504f9574d3fc5251d6478112814aa654d42b3075a4443c5fd69d223479ee0a150845ae8492d28a663372a9ed9dfad4f1a4c2e1a70e362dd509de2770d07a0cb05e215e9bcfe849041071f428ce8b1eb8c64f6fad0b74dd4125c76bd7054bd730a2d2d9b3a5acfa43b94eb37294b2bacff055a33eb4e1758686c79b984b5771c52bcb18f819b1d488d256e932494714be64d2d1518918168ddf08d918b31f8107bb55164e6003f3669f6b6d04465818d50353f4e76acd2ba9752c
#TRUST-RSA-SHA256 319e40ef9beed486d878b05cb4111f040739f3e94ca5dc618f6f2f0e3d93e604fdf624cedd1a33c6168833d471213e3852c7291e08df44c308d15bc0c3b958e7b4e7e2b619c407ef128c0eb206db685c590cd84137f0d7a70d64a93ab5c0b860f4c3b13d6aa98f8a4ae6f47fdc7bccb849711f9dec59ad752f733bfeb17949be199ce60acb297f0e572fcb495c971e316fafe80cdd29e843859eb9ada13eefd7db72d8351ca2da7779fa9a82ffb3b879706c7488fbef89d9f2a9fa6c68f237d2440312057855be121a49db32229efb93e70ed22265aa96160b4660fdb0dcc0cee2683407ccda0a658a04fb95166f69e3b0f08478bc3a8ddafb6ee8f11256698ec985ec98bdf5a0b4db310c2073122f7b755a92eb61ffb464a06b0ee338cf8be62bd381b5fb82afce2f5685ca5a6aceb6e8ea835dde8351e7019fbf4dd66639cb3c7af7d4d1272fde0ac4cc6396a2944e9eb0f20c0cbfc1abb67c4d4c369a0f0f9bc252ef32003239cfd14ca27e2c4093fabd4ab23e7f9c486192fad5292a3200cfaed08c3b16dc1344b5eeda8c1be0b0c482934bc537f8e437260cd935d7442aef12a1a6d771a42e68d01288f34cd70e7e9fcfd960169f62c78cb53540c5ef258479b52cce5b84c9bfecbcd2a179acd61f899c1e63f3b123be5fd667ecae4d1454a1260d765ebc596c745c95acf2b968c1bdef4fe5be7d86abce47444a054b2b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86610);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-7750");

  script_name(english:"Juniper ScreenOS < 6.3.0r20 L2TP DoS (JSA10704)");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS prior to
6.3.0r20. It is, therefore, affected by a denial of service
vulnerability related to the handling of L2TP packets. An
unauthenticated, remote attacker can exploit this, via specially
crafted L2TP packet, to cause the system to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10704");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS 6.3.0r20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


enable_ssh_wrappers();

##
# Only systems with l2tp configured are vulnerable
##
function l2tp_configured()
{
  local_var ret,buf;

  ret = ssh_open_connection();
  if(!ret)
    exit(1, "ssh_open_connection() failed.");
  buf = ssh_cmd(cmd:'get config | include "l2tp"', nosh:TRUE, nosudo:TRUE, noexec:TRUE, cisco:FALSE);
  ssh_close_connection();
  if("set l2tp" >< tolower(buf))
    return TRUE;
  return FALSE;
}

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
version = get_kb_item_or_exit("Host/Juniper/ScreenOS/version");
csp = get_kb_item("Host/Juniper/ScreenOS/csp");

if(isnull(csp))
  csp = "";

# Remove trialing 'a' if there, no 'a' versions fixes this
version = ereg_replace(pattern:"([0-9r\.]+)a$", replace:"\1", string:version);

# Check version
display_fix = "6.3.0r20";
fix = str_replace(string:display_fix, find:'r', replace:'.');

# CSPs
if(version =~ "^6\.3\.0\.13($|[^0-9])" && csp =~ "^dnd1")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
if(version =~ "^6\.3\.0\.18($|[^0-9])" && csp =~ "^dnc1")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

# If we're not 6.3.x or if we are greater than or at fix version, audit out
if(ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

# We have various version sources for this, not all rely on local checks
note = FALSE; # Similar to cisco caveat
if(!isnull(get_kb_item("Host/local_checks_enabled")))
{
  if(!l2tp_configured())
    audit(AUDIT_HOST_NOT, "affected because l2tp is not enabled");
}
else
{
  note =
   '\n  Note: Nessus could not verify that L2TP is configured because' +
   '\n        local checks are not enabled. Only devices using L2TP'+
   '\n        are potentially vulnerable.';
}

port = 0;
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fix;
  if(note)
    report += note;
  report += '\n';

  security_warning(extra:report, port:port);
}
else security_warning(port);
