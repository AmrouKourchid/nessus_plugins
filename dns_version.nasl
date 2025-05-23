##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(72779);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_xref(name:"IAVT", value:"0001-T-0030");
  script_xref(name:"IAVT", value:"0001-T-0937");

  script_name(english:"DNS Server Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to obtain version information on the remote DNS
server.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to obtain version information by sending a special TXT
record query to the remote host.

Note that this version is not necessarily accurate and could even be
forged, as some DNS servers send the information based on a
configuration file.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dns_server.nasl");
  script_require_ports("DNS/udp/53", "DNS/tcp/53");
  exit(0);
}

include("dns_func.inc");
include("byte_func.inc");

var report = '';

var is_tcp = get_kb_item("DNS/tcp/53");
var is_udp = get_kb_item("DNS/udp/53");

if (isnull(is_tcp) && isnull(is_udp)) audit(AUDIT_PORT_CLOSED, 53, "UDP or TCP");

                          # put the more specific queries towards the top,
                          # so they get executed first
var query_strings = make_list("version",
                          "version.maradns",
                          "erre-con-erre-cigarro.maradns.org",
                          "version.mydns",
                          "version.pdns",

                          # multiple products reply to these, so put these last
                          # to help fingerprint servers based on query
                          "version.bind",
                          "version.server");
var query_list = make_list();

# send both uppercase and lowercase query strings to be thorough,
# since some servers are sensitive to case
foreach var query (query_strings)
  query_list = make_list(query_list, query, toupper(query));

var flags = make_list();

if (is_tcp) flags = make_list(flags, TRUE);
if (is_udp) flags = make_list(flags, FALSE);

var proto = "";

var soc, r, len;
foreach is_tcp (flags)
{
  if (is_tcp) soc = open_sock_tcp(53);
  else soc = open_sock_udp(53);

  proto = "UDP";
  if (is_tcp) proto = "TCP";

  if (isnull(soc)) audit(AUDIT_SOCK_FAIL, 53, proto);

  # try every query till we find one that works, and break out
  foreach var q_str (query_list)
  {
    var packet = mk_dns_request(str:q_str,
                                type:DNS_QTYPE_TXT,
                                class:DNS_QCLASS_CH,
                                is_tcp:is_tcp);

    send(socket:soc, data:packet);

    if (is_tcp)
    {
      r = recv(socket:soc, length:2, min:2);
      len = getword(blob:r, pos:0);

      if (len > 4096 || len == 0)
        continue;

      r = recv(socket:soc, length:4096);
    }
    else
      r = recv(socket:soc, length:4096);

    if (!r)
       continue;

    var parsed = dns_data_get(section:"an", type:DNS_QTYPE_TXT, response:r);
    if (isnull(parsed) || isnull(parsed[0]) || strlen(parsed[0]) <= 1)
      continue;

    var version = substr(parsed[0], 1);
    if ( strlen(version) ) set_kb_item(name:"dns_server/version", value:version);
    if ( strlen(q_str) ) set_kb_item(name:"dns_server/version_txt_query", value:q_str);

    report = '\n' + 'DNS server answer for "' + q_str + '" (over ' + proto + ') :' +
             '\n' +
             '\n  ' + version +
             '\n';
    break;
  }

  close(soc);
  if (version) break;
}

if (report != '')
  security_report_v4(port:53, severity:SECURITY_NOTE, proto:tolower(proto), extra:report);
else
  exit(0, "No version information for the DNS server on port 53 was discovered.");
