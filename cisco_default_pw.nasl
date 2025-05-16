#TRUSTED 57a78108d8e3284cdb47f05ce64166a0b61fd2ff9eb63e99110ea7d880e2f84d6ae6a468c189cea6f5f7ef1ad09f628f55ff8fa5ffd181d7ce0abdb55461991150ab4d31f86b44beff67bf299c380fa39368728dee28b8a42c9071e7a037b5dd2350f982fc2c7566c2d44bb9d511a4a1dbe361d83c1a088cbc8152ff15be02ebfed2736386b246dd85d23365a0c6519e8d681cf80486eb7d21305c19dda1150d5f06803840041727f0341e412cf5fde49b4b1b529820d499a29cc1e6548751168ebc3a09e1c527e9a163434eabea9746b80886bbb6cd0e8607ed033e9c962481828d5b5c3e813c333e2c31704322a177ed05ce0eeb2439722b3437ae5dfb3ea760fd0ea1859e0c9cd783b57740cdfda8d4a36b9c405050a16ea143150ba8345f1cfe4410c963ed550ce1f7c13becd4e5704f840c4192629b27a76ca4c7d8fe57c67d087eebe448f6ecb308b4139ba31c15d47a5b03f046dae71375a6f29f537e9ab7ce2f852558beec3562dd3a1983b1bce4c2dfebd7afb520b0db1336f463f64c7aff2e7cdb80284b92ada3bfbcba1bebdf7208128880ad7bfc633498a58105b48f3550e2a4c1e1e04327d6d84887c86c156809a9f8af9e59ee3b18d0621a99c991a011db1f388cd2bd17c3f519e7504ace1ec92d8d740f2aff1b1edd58f8cf3d415163f2080f2670cb5cea149aeca5202591e2f0671744ebf1909593ff2bec
#TRUST-RSA-SHA256 394729b72dcfa3d282870dc3bfb5c4ab23d13005cce9366be925c0e0c6c761bda0a2f45d3f6cd2553d4e74402b8ddf9be9fdfee6a946dbe6ad72bd0fe2ef0cc43c649d34ae589a31d9266b751545da642c9a52cb0a46e34cc36e79c961496daa8b7ec28377972ebe8bf85ba6e438fb3954d1a6d5473a9fc561e652b1c874a42887f78f4aed9b42679dfd38961fa096a08810a2ee2d6f11e67231bcff5fba7711039cfaf9e57ca9459728b160fdc55cd6e4e3ba002ddb6de0b0635161a824bdc789580e0bff823e9981e5e615b0e2f1994eeceabc086a46f13dcc4ca3583e061481fedb6601a318b010a961c84cf2a4e350ccb701edc5328edbdc9236d5161d4c1cbaecbbca9f7f75168aa1c10b08ffde50cdc49bab0d95cbdff2e9aa002bbbbdbc35c876d12cb4da9d9aea83da7459b590a320ff4b20b45e87661c1fa9fbcf5b00200582f2d4dafda340fb8b1c69f5029d378982c6d84fe9f03f398ce2e46088a89e2ccd2a589c798908accc05cc04cc85372461084c1f040cd59f18aaaabe98cdfbffb3fed01b07dfdac0d14dbda5e9e4d6098dafe6dc06a613cb9594f2183198cba824edd70630d2dbb3395ace1a63b41c5c81ca6f8005ce8ea86c26d2138eee8b19a4193b0b1c12b5fc5de40abc3f34a4b2bf951a6d1e80807b1757595ae5cdb3a247e3db05ef017bee7d3ac45d7f01cff8b6d9476a9e5a27e4fc9833ac5b
#
# This script was written by Javier Fernandez-Sanguino
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
# with contributions by Gareth M Phillips <gareth@sensepost.com> (additional logins and passwords)
#
# GPLv2
#
# TODO:
# - dump the device configuration to the knowledge base (requires
#   'enable' access being possible)
# - store the CISCO IOS release in the KB so that other plugins (in the Registered
#   feed) could use the functions in cisco_func.inc to determine if the system is
#   vulnerable as is currently done through SNMP (all the CSCXXXX.nasl stuff)
# - store the user/password combination in the KB and have another plugin test
#   for common combinations that lead to 'enable' mode.
#
# Changes by Tenable:
# - Coding changes regarding Cisco IOS XR/XE, along with some minor
#   tweaks in description block, were done (2017/01/13).

include("compat.inc");

if (description)
{
  script_id(23938);
  script_version("1.51");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-1999-0508");

  script_name(english:"Cisco Device Default Password");
  script_summary(english:"Checks for a default password.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device has a default factory password set.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco router has a default password set. A remote,
unauthenticated attacker can exploit this to gain administrative
access.

Note: To avoid account lockouts and other adverse impacts on the
target host, this plugin will only attempt up to three login combinations
per host under default policy configurations. To test with additional
login combinations, users will need to either disable 'Safe Checks' in
their scan policy or use a PCI scan policy.

Be aware that disabling 'Safe Checks' can result in adverse impacts
on target devices, so be sure to use discretion when disabling this
option.");
  script_set_attribute(attribute:"solution", value:
"Change the Cisco device default password via the command 'enable secret'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0508");
  script_set_attribute(attribute:"cvss_score_rationale", value:"AV:N is justified since the plugin tries to login via SSH or Telnet. While the NVD score implies the the device is only accessible locally, that's not explicitly specified in the CVE description: An account on a router, firewall, or other network device has a default, null, blank, or missing password. It is a reasonable assumption that if the plugin can log in with one of the sets of credentials attempted in the plugin, it can own the device (hence CIA complete instead of partial).");
  script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2006-2024 Javier Fernandez-Sanguino and Renaud Deraison");

  script_dependencies("find_service2.nasl", "ssh_get_info.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("ssh_func.inc");


enable_ssh_wrappers();

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

global_var ssh_port, telnet_checked, telnet_port, ssh_found, telnet_found;
global_var cisco_pw_report_ssh, cisco_pw_report_telnet;
cisco_pw_report_ssh = "";
cisco_pw_report_telnet = "";

cisco_pw_report = "";
ssh_found = FALSE;
telnet_found = FALSE;

# Function to connect to a Cisco system through telnet, send
# a password

function check_cisco_telnet(login, password, port)
{
 local_var msg, r, r2, soc, report, pass_only;
 local_var i, info, line, ver;

 pass_only = TRUE;
 soc = open_sock_tcp(port);
 if ( ! soc )
 	{
	  telnet_port = 0;
	  return(0);
	}
 msg = telnet_negotiate(socket:soc, pattern:"(ogin:|asscode:|assword:)");
 if(strlen(msg))
 {
  # The Cisco device might be using an AAA access model
  # or have configured users:
  if ( stridx(msg, "sername:") != -1 || stridx(msg, "ogin:") != -1  )  {
    send(socket:soc, data:login + '\r\n');
    msg=recv_until(socket:soc, pattern:"(assword:|asscode:)");
    pass_only = FALSE;
  }

  # Device can answer back with {P,p}assword or {P,p}asscode
  # if we don't get it then fail and close
  if ( strlen(msg) == 0 || (stridx(msg, "assword:") == -1 && stridx(msg, "asscode:") == -1)  )  {
    close(soc);
    return(0);
  }

  send(socket:soc, data:password + '\r\n');
  r = recv(socket:soc, length:4096);

  # TODO: could check for Cisco's prompt here, it is typically
  # the device name followed by '>'
  # But the actual regexp is quite complex, from Net-Telnet-Cisco:
  #  '/(?m:^[\r\b]?[\w.-]+\s?(?:\(config[^\)]*\))?\s?[\$\#>]\s?(?:\(enable\))?\s*$)/')

  # Send a 'show ver', most users (regardless of privilege level)
  # should be able to do this
  send(socket:soc, data:'show ver\r\n');
  r = recv_until(socket:soc, pattern:"(Cisco (Internetwork Operating System|IOS|Adaptive Security Appliance) Software|assword:|asscode:|ogin:|% Bad password|% Login invalid)");
  # TODO: This is probably not generic enough. Some Cisco devices don't
  # use IOS but CatOS for example

  # TODO: It might want to change the report so it tells which user / passwords
  # have been found
  if (
     strlen(r) &&
     (
       "Cisco Internetwork Operating System Software" >< r ||
       "Cisco IOS Software" >< r ||
       "Cisco IOS XR Software" >< r ||
       "Cisco IOS XE Software" >< r ||
       "Cisco Adaptive Security Appliance Software" >< r
     )
  )
  {
    r2 = recv_until(socket:soc, pattern:'^System image file is "[^"]+"');
    if (strlen(r2)) r = strstr(r, "Cisco") + chomp(r2) + '\n' + '(truncated)';

    ver = egrep(pattern:"^.*IOS.*Version [0-9.]+(?:\(.*\))?.*", string:r);
    if (ver) {
        if ( !get_kb_item("Host/Cisco/show_ver" ) )
  		set_kb_item(name:"Host/Cisco/show_ver", value:ereg_replace(string:ver, pattern:".*(Cisco.*)", replace:"\1"));
	info = '\n  ' + chomp(ver);
    }
    else
    {
      info = '';
      i = 0;
      foreach line (split(r, keep:FALSE))
      {
        if (++i >= 5) break;
        info += '\n  ' + line;
      }
    }
    telnet_found = TRUE;

    report =
      '\n' + 'It was possible to log into the remote Cisco device via Telnet' +
      '\n' + 'using the following credentials :' +
      '\n';
    if (!pass_only) {
      report +=
        '\n' + '  User     : ' + login;
    }
    report +=
      '\n' + '  Password : ' + password +
      '\n' +
      '\n' + 'and to run the \'show ver\' command, which returned in part :'+
      '\n' +
      info + '\n';
    if (get_kb_item("Settings/PCI_DSS"))
      cisco_pw_report_telnet += '\n' + report;
    else
      security_hole(port:port, extra:report);
  }

# TODO: it could also try 'enable' here and see if it's capable
# of accessing the privilege mode with the same password, or do it
# in a separate module

  close(soc);

 }
}

# Functions modified from the code available from default_accounts.inc
# (which is biased to UNIX)
function check_cisco_account(login, password)
{
 local_var port, ret, banner, soc, res, report;
 local_var buf, i, info, line, ver;

 checking_default_account_dont_report = TRUE;

 if (ssh_port && get_port_state(ssh_port))
 {
  # Prefer login thru SSH rather than telnet
   _ssh_socket= open_sock_tcp(ssh_port);
   if ( _ssh_socket)
   {
   ret = ssh_login(login:login, password:password);
   if (ret == 0) buf = ssh_cmd(cmd:"show ver", nosh:TRUE, nosudo:TRUE, cisco:TRUE);
   else buf = "";
   ssh_close_connection();
   if (
     buf &&
     (
       "Cisco Internetwork Operating System Software" >< buf ||
       "Cisco IOS Software" >< buf ||
       "Cisco IOS XR Software" >< buf ||
       "Cisco IOS XE Software" >< buf ||
       "Cisco Adaptive Security Appliance Software" >< buf
     )
   )
   {
     ver = egrep(pattern:"^.*IOS.*Version [0-9.]+(?:\(.*\))?.*", string:buf);
     if (ver) {
	info = '\n  ' + chomp(ver);
    	if ( !get_kb_item("Host/Cisco/show_ver" ) )
		set_kb_item(name:"Host/Cisco/show_ver", value:ereg_replace(string:ver, pattern:".*(Cisco.*)", replace:"\1"));
	}
     else
     {
       info = '';
       i = 0;
       foreach line (split(buf, keep:FALSE))
       {
         if (++i >= 5) break;
         info += '\n  ' + line;
       }
     }
     ssh_found = TRUE;

     report =
       '\n' + 'It was possible to log into the remote Cisco device via SSH' +
       '\n' + 'using the following credentials :' +
       '\n' +
       '\n' + '  User     : ' + login +
       '\n' + '  Password : ' + password +
       '\n' +
       '\n' + 'and to run the \'show ver\' command, which returned in part :'+
       '\n' +
       info + '\n';
     if (get_kb_item("Settings/PCI_DSS"))
       cisco_pw_report_ssh += '\n' + report;
     else
       security_hole(port:ssh_port, extra:report);
   }
   }
   else
     ssh_port = 0;
 }

 if(telnet_port && get_port_state(telnet_port))
 {
  if ( isnull(password) ) password = "";
  if ( ! telnet_checked )
  {
  banner = get_telnet_banner(port:telnet_port);
  if ( banner == NULL ) { telnet_port = 0 ; return 0; }
  # Check for banner, covers the case of Cisco telnet as well as the case
  # of a console server to a Cisco port
  # Note: banners of cisco systems are not necessarily set, so this
  # might lead to false negatives !
  if ( stridx(banner,"User Access Verification") == -1 && stridx(banner,"assword:") == -1)
    {
     telnet_port = 0;
     return(0);
    }
   telnet_checked ++;
  }

  check_cisco_telnet(login:login, password:password, port:telnet_port);
 }
 if (get_kb_item("Settings/PCI_DSS")) return 0;
 if (ssh_found || telnet_found) exit(0);
 return(0);
}

ssh_port = get_kb_item("Services/ssh");
if ( ! ssh_port ) ssh_port = 22;


telnet_port = get_kb_item("Services/telnet");
if ( ! telnet_port ) telnet_port = 23;
telnet_checked = 0;

check_cisco_account(login:"cisco", password:"cisco");
check_cisco_account(login:"Cisco", password:"Cisco");
check_cisco_account(login:"", password:"");
if ( safe_checks() == 0 || get_kb_item("Settings/PCI_DSS"))
{
 check_cisco_account(login:"cisco", password:"");
 check_cisco_account(login:"admin", password:"cisco");
 check_cisco_account(login:"admin", password:"diamond");
 check_cisco_account(login:"admin", password:"admin");
 check_cisco_account(login:"admin", password:"system");
 check_cisco_account(login:"monitor", password:"monitor");
}

if (get_kb_item("Settings/PCI_DSS"))
{
  if(ssh_found)
    security_hole(port:ssh_port, extra:cisco_pw_report_ssh);
  if(telnet_found)
    security_hole(port:telnet_port, extra:cisco_pw_report_telnet);
  else
    exit(0,"Host not affected.");
}
