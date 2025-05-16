##
# (C) Tenable, Inc.
##
# @PREFERENCES@

include("compat.inc");

if (description)
{
  script_id(58038);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/22");

  script_name(english:"LDAP 'Domain Admins' Group Membership Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to list the members of the 'Domain Admins' group on
the remote LDAP server.");
  script_set_attribute(attribute:"description", value:
"By using the search base gathered by plugin ID 25701 and the supplied credentials, Nessus was able to enumerate the list of members of the
'Domain Admins' group in the remote LDAP directory. Several Domain Admins groups may be returned if the LDAP port corresponds to a Global Catalog server (i.e. 3268/3269)");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2024 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  script_add_preference(name:"LDAP user : ", type:"entry", value:"");
  script_add_preference(name:"LDAP password : ", type:"password", value:"");
  script_add_preference(name:"Max results : ", type:"entry", value:"1000");

  exit(0);
}

include('ldap_func.inc');
include('lists.inc');
include('json2.inc');
include('der_funcs.inc');
include('smb_func.inc'); # for sid2string()
include('string.inc');

##
# Converts all elements of a parsed LDAP search entry into strings. objectSid are parsed using sid2string() and
# objectGUID are convered from bytes to formatted objectGUID.
#
# @param parsed_search_entry A nested list which is the result of a call to ldap_parse_search_entry() in ldap_func.inc
#
# @return A nested list with no binary elements
function elts_to_strings(parsed_search_entry)
{
  var new_parsed_search_entry = make_nested_list();
  var new_elt;
  foreach var elt (parsed_search_entry)
  {
    if (tolower(elt[0]) == 'objectsid' && !isnull(elt[1][0]))
    {
      new_elt = make_nested_list
      (
        elt[0],
        make_nested_list('S-' + sid2string(sid:elt[1][0]))
      );
      append_element(var:new_parsed_search_entry, value:new_elt);
    }
    else if (tolower(elt[0]) == 'objectguid' && !isnull(elt[1][0]))
    {
      new_elt = make_nested_list
      (
        elt[0],
        make_nested_list(bytes_to_formatted_guid(bytes:elt[1][0]))
      );
      append_element(var:new_parsed_search_entry, value:new_elt);
    }
    else
    {
      append_element(var:new_parsed_search_entry, value:elt);
    }
  }
  return new_parsed_search_entry;
}

# ############ #
# ##  Main  ## # 
# ############ #
var port = get_service(svc:'ldap', exit_on_fail:true);
var ldap_user = script_get_preference('LDAP user : ');
var ldap_pass = script_get_preference('LDAP password : ');
var max_results = script_get_preference('Max results : ');
if (!max_results)
{
  max_results = 1000;
}
else
{
  max_results = int(max_results);
  if (max_results <= 0) max_results = 1000;
}

var list = get_kb_list('LDAP/' + port + '/namingContexts');
if (isnull(list)) exit(0, 'The LDAP/' + port + '/namingContexts KB list is missing.');
list = make_list(list);

var domain = NULL;
var domain_obj = NULL;
var ret;
foreach var namingcontext (list)
{
  # Look for the DC= elements, but leave out DomainDnsZones and ForestDnsZones
  ret = ldap_extract_dc(namingcontext:namingcontext);
  if (ret['obj'])
  {
    domain_obj = ret['obj'];
    domain = ret['domain'];
    break;
  }
}
if (isnull(domain_obj)) exit(1, 'Couldn\'t extract the domain information from the namingcontexts for the LDAP server listening on port ' + port + '.');

# In some cases the user name needs to be in the form of user@domain.  If the username doesn't contain @domain, append it to the username
domain = '@' + domain;
if ('@' >!< ldap_user) ldap_user += domain;

# Initiate the ldap connection
var soc = open_sock_tcp(port);
if (!soc) exit(1, 'Can\'t open socket on port ' + port + '.');
ldap_init(socket:soc);

# Bind to the LDAP server, using credentials if they are supplied
if (!empty_or_null(ldap_user) && !empty_or_null(ldap_pass))
{
  var bind = ldap_bind_request(name:ldap_user, pass:ldap_pass);
  ret = ldap_request_sendrecv(data:bind);
  if (isnull(ret) || ret[0] != LDAP_BIND_RESPONSE) exit(1, 'Failed to bind to the LDAP server listening on port ' + port + '.');

  # Make sure authentication was successful
  ret = ldap_parse_bind_response(data:ret[1]);
  if (ret[0] == LDAP_INVALID_CREDENTIALS) exit(1, 'Failed to authenticate to the LDAP server listening on port ' + port + ' using the supplied credentials.');
}

# Enumerate Domain Admins groups
var control = ldap_paged_results_ctrl(size:1000);
var filter = [{'left':'objectClass', 'conditional':LDAP_FILTER_EQUAL, 'right':'group'}];
var attributes = ['distinguishedName','objectSid', 'objectGUID', 'member'];
var search = ldap_search_request(object:domain_obj, filter:filter, attributes:attributes, scope:0x02, controls:[control]);
ldap_start_search(data:search);

var rep, result, group, attr, sid, guid, dn, members;
var domain_admins_groups = [];
var total_results = 0;
repeat {
  rep = ldap_recv_search_advanced(auto_page:true, full_values:true);
  if (!empty_or_null(rep.results))
  {
    foreach result (rep.results)
    {
      if (total_results++ < max_results)
      {
        group = elts_to_strings(parsed_search_entry:result);
        dbg::detailed_log(lvl:3, msg:'elts_to_strings(result): ' + obj_rep(group));
        sid = guid = dn = members = NULL;
        foreach attr (group)
        {
          if (empty_or_null(attr[0])) break;
          else if (attr[0] == 'objectSid' && !isnull(attr[1][0])) sid = attr[1][0];
          else if (attr[0] == 'objectGUID' && !isnull(attr[1][0])) guid = attr[1][0];
          else if (attr[0] == 'distinguishedName' && !isnull(attr[1][0])) dn = attr[1][0];
          else if (attr[0] == 'member' && !isnull(attr[1])) members = attr[1];
        }
        if (sid !~ "-512$") continue; # well-known RID for Domain Admins group https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ba46366-add7-43b1-821a-1640cf616ebc
        append_element(var:domain_admins_groups, value:{'dn':dn, 'sid':sid, 'guid':guid, 'member':members});
      }
    }
  }
  if (!empty_or_null(rep['next_page'])) search = rep.next_page;
  else search = NULL;
} until (empty_or_null(search));

if (empty_or_null(domain_admins_groups))
  exit(0, 'Nessus wasn\'t able to find any Domain Admins group in the LDAP server listening on port ' + port + '.');

# Enumerate members of each Domain Admins group we found earlier
var json_group, resp, member_index, member_dn;
var report = '';
var first = true;
var domain_admins_json = [];
var group_index = 0;
attributes = ['objectSid', 'objectGUID'];
foreach group (domain_admins_groups)
{
  json_group = {'distinguishedName':group.dn, 'objectGUID':group.guid, 'objectSid':group.sid, 'member':[]};
  set_kb_item(name:strcat('LDAP/DomainAdmins/', group_index, '/distinguishedName') , value:group.dn);
  set_kb_item(name:strcat('LDAP/DomainAdmins/', group_index, '/objectGUID') , value:group.guid);
  set_kb_item(name:strcat('LDAP/DomainAdmins/', group_index, '/objectSid') , value:group.sid);

  if (!empty_or_null(group.member))
  {
    # set spacing after first group has been reported
    if (first) first = false;
    else report += '\n\n';
    report += strcat('Nessus enumerated the following members of this Domain Admins group: ', group.dn, '\n');
  }
  member_index = 0;
  foreach member_dn (group.member)
  {
    search = ldap_search_request(object:member_dn, filter:[], attributes:attributes, scope:0x02, controls:[control]);
    ldap_start_search(data:search);
    repeat {
      rep = ldap_recv_search_advanced(auto_page:true, full_values:true);
      if (!empty_or_null(rep.results))
      {
        foreach result (rep.results)
        {
          sid = guid = members = NULL;
          resp = elts_to_strings(parsed_search_entry:result);
          foreach attr (resp)
          {
            if (empty_or_null(attr[0])) break;
            else if (attr[0] == 'objectSid' && !isnull(attr[1][0]))
            {
              sid = attr[1][0];
              set_kb_item(name:strcat('LDAP/DomainAdmins/', group_index, '/Members/', member_index, '/sid') , value:sid);
            }
            else if (attr[0] == 'objectGUID' && !isnull(attr[1][0]))
            {
              guid = attr[1][0];
              set_kb_item(name:strcat('LDAP/DomainAdmins/', group_index, '/Members/', member_index, '/guid') , value:guid);
            }
          }
          append_element(var:json_group.member, value:{'distinguishedName':member_dn, 'objectGUID':guid, 'objectSid':sid});
          member_index++;
          report += strcat('  | ', member_dn, '\n');
        }
      }
      if (!empty_or_null(rep['next_page'])) search = rep.next_page;
      else search = NULL;
    } until (empty_or_null(search));
  }
  append_element(var:domain_admins_json, value:json_group);
  group_index++;
}
var json = json_write(domain_admins_json);
report_xml_tag(tag:'Domain_admins_members', value:json);
security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
