#TRUSTED 5304104476a27a0bc927e7836870dfa25be87d9daea99ff280fd0bc5406fb9f40299b83b146b77bd5af3a8fbe2fb2baca4a0dc68eee3974bb0dc329777af0b7a3bab967fcd3ab03ecd78765f59be38bff35384a1e62390f7dde039e2278e633fdce6113ca218d3e716f1eaef790db87dd8ad00f646e38013a1f230574b4450608c2c2615e6f57d5a4012ff94df6183982b6ef2c611ab3958d445452c3fa42a2dee97f644fe8037014857bbe6e8ad63aa07e642a3a0e0357dc2a476e590dc3bb17e299c96bfd14fcaec7afd38036e80d26e98769a6d5fee78ad4b54456c92fef11b779d76244ebcc7a5271c079854d6fe582eab06107b64df3f236fffc7abd2c59283208be6143097100d72f91f86116e3c0ce6d745cc425cf5d4eb79b28b786f8b39632273f449700fb6f8385c402f27bf28f787c2fd59e64903dd1367161150689c35e0438b9b775520f70ea9a9ece288308d043a0046676654e8981bca1010e3fc20ffd88f49471b0ffe68f29bcf0aae884b2a649f9cfef029a102da0c8f7eafb21a8d06ba1af58334cbdf0d5980f37e66de37d75840f4fa5041bbe627f7f2d94c390495ddd65035ff0076178257544c2841bd1aa3dc0127386c8f182b64242bd0956b8918276cd6fa636202bca68857a05ab049927664cfe233bbe038fb9ae2c0e46690576b5b3bf699085a96d51aea304b6c07f9832dc08adb6891e7db5d
#TRUST-RSA-SHA256 2ce3e38b7134f1b1857921b9c36103f3107fd3c0fd83b210de74d18e0df182cff0b387e208410100152a235dcce46153e3d436ff78a04105799a38b606e4817f2c086b9be8b02877b2b1855db4bc8effa41734bcdc101cc3d4d66969978c307f93fab9113e26e45e1194e41c8b96a5f861db0aca63803869b9c7d0b0b0d6f85807803b2e8696f5e27a06e6dc7db579aa481df8fe7b63ca1ec063f0e5129c93f2135da6262198312d5a91801cf70c3006049da489b9a4b0315b4f4a6d9158d34e6700b88d2da27308aacccfd53463125c206dd1b2470c881b093e4ad859e9bf9bd5f5fa4ec2e45d1cd423cd0e40dd43fe99173a667d53b4ac9778bc226f4bf4faf57e6742be531d9fc34437bcc034437219db88dc12193f89826e52c271a8347ca442d2e1ae2c7d128223d3fde7193fc3dbaad08b9196bf72797ad363a0355c1d2172b1eed937315d804b3da53e0d27b2fe986bb412ea9ce31e3c9b4db03ca349e3622b8caa8da79b539ed26204ef86583956c422379719cb8c021b7d54a65d578914391df9e4dffa8e12104c970062f418d547ea0917b6343f67ad944fca3536149a63bff227d2dd5bcee567d5c141e0ed8a8e196d8878490e9385c072402989b1007cd3322d873699b27cc1ae3cbdc69e2b83821cafed1a939f7f1a2c887688b86daf8c93dfa494bad3e364e0c23a95a5ecbfcb0df52e2aef173b2b151b3e50
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63340);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X Wireless Networks List");

  script_set_attribute(attribute:"synopsis", value:"The remote host has connected to wireless networks in the past.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, it is possible to extract the list of
networks to which the remote host has connected in the past.");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of Wi-Fi networks is done in accordance to your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X"); 

report = NULL;

preferences = [ 'KnownNetworks', 'RememberedNetworks' ];

foreach preference (preferences)
{
  cmd = strcat('defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences ', preference, ' | egrep "(SSIDString|LastConnected|SecurityType)"');

  res = exec_cmd(cmd:cmd);
  if ( "SSIDString =" >!< res ) continue;
  array = split(res, keep:FALSE);
  flag = 0;
  foreach line ( array )
  {
   if ( "LastConnected" >< line )
    date = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*LastConnected = (.*);$", string:line, replace:"\1"));
   else if ( "SecurityType" >< line )
   {
    security = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*SecurityType = (.*);$", string:line, replace:"\1"));
    flag = 1;
   }
   else if ( "SSIDString" >< line )
   {
    network = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*SSIDString = (.*);$", string:line, replace:"\1"));
    flag = 1;
   }

   if( (strlen(network) > 0 && strlen(security) > 0) ||
       (strlen(date) > 0 && strlen(network) > 0 && flag == 0 ) )  # In case there's no "SecurityType" associated to the remote network
   {
    report += '-  Network name : ' + network;
    if ( flag != 0 )
    {
     if ( strlen(date) ) report += '\n   Last connected : ' + date;
     else report += '\n   Last connected : N/A';
     date = NULL;
    }
    if ( strlen(security) )
    {
     report += '\n   Security: ' + security;
    }
    network = security = NULL;
    flag = 0;
    report += '\n\n';
   }
  }
  break;
}

if (empty_or_null(report))
  exit(0, "Could not extract the list of Wi-Fi networks.");

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

