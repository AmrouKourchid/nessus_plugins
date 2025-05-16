#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10280);
 script_version("1.46");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/26");
 
  script_xref(name:"IAVA", value:"0001-A-0630");

 script_name(english:"Telnet Service Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"Telnet service appears to be running on the remote system." );
 script_set_attribute(attribute:"description", value:
"The Telnet service is running. This service is dangerous in 
the sense that it is not ciphered - that is, everyone can 
sniff the data that passes between the telnet client and 
the telnet server. This includes logins and passwords." );
 script_set_attribute(attribute:"solution", value:
"If you are running a Unix-type system, OpenSSH can be used 
instead of telnet. For Unix systems, you can comment out the 
'telnet' line in /etc/inetd.conf. For Unix systems which use 
xinetd, you will need to modify the telnet services file in the
/etc/xinetd.d folder.  After making any changes to xinetd or 
inetd configuration files, you must restart the service in order
for the changes to take affect.

In addition, many different router and switch manufacturers 
support SSH as a telnet replacement. You should contact your vendor 
for a solution which uses an encrypted session." );
 script_set_attribute(attribute:"risk_factor", value:"None" );



 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks for the presence of Telnet");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Service detection");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("telnet_func.inc");
include("misc_func.inc");


var banner = NULL;
var port = get_service(svc: "telnet", default: 23, exit_on_fail: 1);
var soc = open_sock_tcp(port);

# Check port first so we can report
# network problems if need be
if (!soc)
{
  banner = get_kb_item_or_exit('Services/telnet/banner/' + port);
  dbg::detailed_log(
    lvl:1,
    src:SCRIPT_NAME,
    msg:'Port ' + port + ' is not respondinng now even though it was ' +
        'previously responding. Will continue with KB data.'
  );
}
else
{
  banner = telnet_negotiate(socket:soc);
  close(soc);
}

if(empty_or_null(banner))
  audit(AUDIT_RESP_BAD, port);

set_telnet_banner(port: port, banner: banner);
register_service(port:port, proto:"telnet");
