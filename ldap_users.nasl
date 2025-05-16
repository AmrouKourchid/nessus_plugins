#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45478);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/01");

  script_name(english:"LDAP User Enumeration");
  script_summary(english:"Retrieves the list of users via LDAP.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to get the list of users on the remote LDAP server.");
  script_set_attribute(attribute:"description", value:
"By using the search base gathered by plugin ID 25701, Nessus was able
to enumerate the list of users in the remote LDAP directory.");
  script_set_attribute(attribute:"solution", value:
"Configure the LDAP server to require authentication.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");
include("data_protection.inc");

var ports = get_service_port_list(svc:"ldap", exit_on_fail:TRUE);

var msg, port;
msg = "LDAP Ports found: " + obj_rep(ports);
dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);

foreach port (ports)
{
  msg = "LDAP Port " + obj_rep(port);
  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);

  var list = get_kb_list('LDAP/'+port+'/namingContexts');
  if (isnull(list))
  {
    msg = 'The LDAP/'+port+'/namingContexts KB list is missing.';
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);
    continue;
  }
  list = make_list(list);


  var obj = NULL;
  foreach var namingcontext (list)
  {
    # Look for the DC= elements
    if ('DC=' >< namingcontext || 'dc=' >< namingcontext)
    {
      var dcret = ldap_extract_dc(namingcontext:namingcontext);
      obj = dcret['obj'];
      break;
    }
  }


  if (isnull(obj))
  {
    msg = "Couldn't extract the domain information from the namingcontexts for the LDAP server listening on port "+port+".";
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);
    continue;
  }

  var soc = open_sock_tcp(port);
  if (!soc)
  {
    msg = "Can't open socket on port "+port+".";
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);
    continue;
  }

  ldap_init(socket:soc);

  var search_filters = make_nested_list(
    make_array(
      "object", "cn=users," + obj,
      "filter", "person",
      "scope", 0x01
    ),
    make_array(
      "object", obj,
      "filter", "posixAccount",
      "scope", 0x02
    ),
    make_array(
      "object", obj,
      "filter", "person",
      "scope", 0x02
    )
  );


  var i = 0;
  var report = NULL;
  var users = make_array();
  foreach var search_val (search_filters)
  {
    var filter = make_array();
    filter["left"] = "objectClass";
    filter["conditional"] = LDAP_FILTER_EQUAL;
    filter["right"] = search_val["filter"];

    var filters = make_list();
    filters[0] = filter;

    var search = ldap_search_request(object:search_val["object"], filter:filters, scope:search_val["scope"]);    
    var ret = ldap_request_sendrecv(data:search);

    repeat {
      if (isnull(ret) || ret[0] != LDAP_SEARCH_RES_ENTRY)
        break;
      var data = ldap_parse_search_object_name(data:ret[1]);
      var user_str = string (data - strcat(",", obj));
      users[user_str] = 1;
      ret = ldap_recv_next();
    }   until ( isnull(ret));
  }

  # eliminate duplicates in report by using array
  var count = 0;
  foreach var user (keys(users))
  {
    count++;
    set_kb_item(name:strcat("LDAP/",port,"/Users/",count), value:user);
    user = data_protection::sanitize_user_enum(users:user);
    report += strcat("   |  ", user, "\n");
  }
  if (count > 0) set_kb_item(name:"LDAP/"+port+"/Users/count", value:count);

  if ( strlen(report) > 0 ) 
  {
   if (report_verbosity > 0)
   {
    report = "[+]-users : \n" + report;
    security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
   }
   else
   {
    security_report_v4(severity:SECURITY_NOTE, port:port);
   }
  }
}    # end of foreach port (ports) loop



