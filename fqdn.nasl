#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12053);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

 script_name(english:"Host Fully Qualified Domain Name (FQDN) Resolution");
 script_summary(english:"Performs a name resolution.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to resolve the name of the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to resolve the fully qualified domain name (FQDN) of
the remote host.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");

 script_copyright(english:"This script is Copyright (C) 2004-2025 Tenable Network Security, Inc.");

 exit(0);
}

include('nessusd_product_info.inc');
# adding agent check as for request in RES-178081
if (nessusd_is_agent())
{
  exit(0, 'This plugin does not run on Nessus Agents');
}
if(!defined_func("nasl_level") || nasl_level() < 6900)
{
  hostname = get_host_name();
}
else
{
  hostname = get_host_fqdn();
}

if ( hostname != get_host_ip() )
{
  if ( !TARGET_IS_IPV6 || tolower(hostname) !~ "^[0-9a-f]+:" )
  {
   set_kb_item(name:"FQDN/Succeeded", value:TRUE);
   set_kb_item(name:"Host/FQDN", value:hostname);
   report = string("\n", get_host_ip(), " resolves as ", hostname, ".\n");
   security_note(port:0, extra:report);
  }
}
