#TRUSTED a0a8a56676ba2daa63fefc63e218342e8f853a776ebb0959b0ac98f78ea765b0e1911019e1f4c2280b29a694ada62f00ac52a3b6244c25f3361bf2c7a85c32705e30294667aa4133ffede95d9317e414c0cc9ca23bc5f5d8631b5b125b1c1d795d49ec6f32e872282cc36ad782a0f841d7b3e0cd448dae688033e9d34e6a0ae4f2e498c45125a8478480f1b79f779ba7455864f62280be376e6caa5a6aadda3077a94f851af9eea5148e57fe9266c4cad14241d510c31438bbe67eb6a9a2e9cadc0408e9f85b88826d45699650817218af36ae0f95aa36b7e6dd2f8223244eb91c7f735ac60e166379143db93372d17f8fd4b0a92aa8510ddff08fff41a5ad66f43dc6636cfa606745a9edfc9854b050bd0b3de6cd8ba32fe75f8b36318ec7b4ac735a02b86262333b579f0c4ea6ba831c8b91d2a95a01e599b74e521a93fe744c5ee9e6f95ad06ad462cb0ff2069d0194535485e6253ca2be26279b3e48c84e3040700c55fee40cdb1b494f80ae3112d17a09508f96d9f2ad7682dde59c776dcf8b2be209eef2d469129a444efbd183c6269907a2ef654ffd1409c946ddbd9438c74757f2f7dcbf17fc374d7167afdfec3865b2dc0f9a5a7b540877c8e3f477a21f7d0fc075e2f3f100d59b599d711feb7e3f807825fe6ed4162b8c6d4c4b7948c0024574f8749e615b94bb9b33bbdf0bbfcd82f68b8f962923f126da12921f
#TRUST-RSA-SHA256 27166f19dc05f3c3bcd8524d6098ef1725cfd9c544c91265565497c4d3a8941717c3ac13303c2730d28809ad6547574d427867c0a067b5b73967c868d6c292ff156cec85dfd8d40404c9a80cc76595c94f75c1890e903fd6dbbd21a7a1c73a004220a5976099b2f60cdb7b2a5922e3dd38bc130107ee620504b0793abcc008b1fa2d241f09bf03ab1a2e820fe275ed5f472074a2f86471a6453d1ac6d880e732acca2c01a142f4bb966a4704bfec7cc8d06ceea68680a7fff2718e62a346a8d77d15f35218a9c7782fe051a0882cc1c9cfb0f701317f8e4e362949d920dbd3141b809d46fb1ffbdba6c30f487674ead4cfce801716aadb046120c7251ee678b55046ce5db3f4aef013ec6678afea859b0146c092adf7fa93f4339dbb3f2722594682c74282b0b7522ebe16da401e4e6b3dc6138c49ba8e5beab1a229487196f065776c9db55571c5816f44c76fcbb9e4b559c9addf0b3e0243848a3815b6b1bd8b1de9d26217999d75aee549cb11b26cccaeb113357641e1c8ca8be58dcf4b38735de74724bd28e9d0dfcb52fd8ed74db454665a9f6ffb7a3c43f6eca170dcad8ea199e54a8e13749ef5cd87905079e4fa1ceb1090431c8f0444cc34b8b72f3b333bc12c955b133aa532a407284dedc65b1c606a13adaefd922913b11bc5a0c4db230707cda85f573d5aa45542eb43e22456411fa571c69566bcb485b150db98
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91457);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2016-3427");
  script_xref(name:"VMSA", value:"2016-0005");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"VMware vSphere Replication Oracle JRE JMX Deserialization RCE (VMSA-2016-0005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a virtualization appliance that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware vSphere Replication running on the remote host is version
5.6.x prior to 5.6.0.6, 5.8.x prior to 5.8.1.2, 6.0.x prior to
6.0.0.3, or 6.1.x prior to 6.1.1. It is, therefore, affected by a
remote code execution vulnerability in the Oracle JRE JMX component
due to a flaw related to the deserialization of authentication
credentials. An unauthenticated, remote attacker can exploit this to
execute arbitrary code.

Note that vSphere Replication is only affected if its vCloud Tunneling
Agent is running, and it is not enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vSphere Replication version 5.6.0.6 / 5.8.1.2 /
6.0.0.3 / 6.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3427");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vsphere_replication");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vSphere Replication/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");
include("misc_func.inc");


enable_ssh_wrappers();

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

version = get_kb_item_or_exit("Host/VMware vSphere Replication/Version");
verui = get_kb_item_or_exit("Host/VMware vSphere Replication/VerUI");
build = get_kb_item_or_exit("Host/VMware vSphere Replication/Build");

fix = '';
vuln = FALSE;

if (version =~ '^5\\.6\\.' && int(build) < 3845873) fix = '5.6.0.6 Build 3845873';
else if (version =~ '^5\\.8\\.' && int(build) < 3845890) fix = '5.8.1.2 Build 3845890';
else if (version =~ '^6\\.0\\.' && int(build) < 3845888) fix = '6.0.0.3 Build 3845888';
else if (version =~ '^6\\.1\\.' && int(build) < 3849281) fix = '6.1.1 Build 3849281';

if (!empty(fix))
{
  sock_g = ssh_open_connection();
  if (! sock_g)
    audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;

  line = info_send_cmd(cmd:"service vmware-vcd status");
  ssh_close_connection();

  if (
    "vmware-vcd-watchdog is running" >< line &&
    "vmware-vcd-cell is running" >< line
  )
  {
    vuln = TRUE;
  }
  else
    exit(0, "vCloud Tunneling Agent does not appear to be running on the VMware vSphere Replication appliance examined (Version " + verui + ").");

}

if (vuln)
{
  report =
    '\n  Installed version : ' + verui +
    '\n  Fixed version     : ' + fix +
    '\n';

   security_report_v4(
    extra    : report,
    port     : '0',
    severity : SECURITY_HOLE
  );
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vSphere Replication', verui);
