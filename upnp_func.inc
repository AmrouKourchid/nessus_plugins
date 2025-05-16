#TRUSTED ad6e26ed62366b50f94f79bc1a8f15073a7de31685744efaccbc19a2d2cc9cabaca4addf64531544a3977f0c6516342910bf683fa438795c0debc4bea635112939631b9a1d3c1e70bad13c6cc50b3ed2af94f7b59ad1e9c0d9c51e9a8c173e39b422d5a9aeec5d37108448dc754a9b748a3347c36b3524226df45f3358919edc03e1a36c0e8b4ddc4d4dd2d65d109aa26c7e5a7930347951e553bff3d4228f7ac96293c7c705a90291d480fe016a103e3e06b1c77def20ab7fa3d1eeb57eb7de65c0011a94da43a4ffb65786e9f94cd3341a0ee3980c28d0511909404afa231eb3ef4ecbb0e131553c825d0db99ec8d87652f4223db673aa1eca04cb255a4db9bf1231a4afd49eae16ff20747a03842b6224834c9da27707c1dff9a0f4ef5dc499e6294557f9fdd8c4f278071783ab9d5591d2f4d167e9388ca522fcc682eeb0d3205386a5632bfc87a161f20d00efd9bdedabede5005be28e7bf4827897c557d80273da356addab63d0fba61c97eff55eecf4a41349c7ab9bd93064ac48555611576858dbc562feb701be6d49c643786a9bb32b93fb1e1ca7e0da73b48cd11a7aaae504c4718ad941d11599f6f79a0c1168f56eb83f521f44cdb60fc679c67950cea3ce8cd4216ad7e325d98dad3eba87b4cb0c8b0eecb47f6d32461bc7e6fed40f5a64d0e513cee8413759f755d759645de30ff8edbaa75cce1f4de6c02a4c

# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# upnp_func.inc 
# Revision 1.4
#

include("http.inc");

##
# Finds the provided service field and extracts the
# index and control url.
# @param xml the xml describing a service
# @param service the service to locate
# @return array - the url and index
##
function upnp_svc_url(xml, svc)
{
  local_var pattern = '<serviceType>urn:schemas-upnp-org:service:' + svc + ':' + '([0-9]+)' + '</serviceType>';
  local_var service = eregmatch(string:xml, pattern:pattern, icase:TRUE);
  if (isnull(service)) return NULL;

  local_var url = eregmatch(string: xml, pattern: "<controlURL>([^<]+)</controlURL>");
  if (isnull(url)) return NULL;

  local_var ret_val = make_array();
  ret_val['url'] = url[1];
  ret_val['index'] = service[1];
  return ret_val;
}

function upnp_find_service(xml, svc)
{
  local_var p, i, u;

  while (1)
  {
    p = strstr(xml, '<service>');
    if (isnull(p)) return NULL;
    i = stridx(p, '</service>');
    u = upnp_svc_url(xml: substr(p, 9, i - 1), svc: svc);
    if (!isnull(u)) return u;
    xml = substr(p, i + 9);
  }

  return NULL;
}

function upnp_make_soap_data(action, svc, fields)
{
  local_var xml, f;

  xml = strcat('<?xml version="1.0"?>\r\n',
 '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\r\n',
 '<SOAP-ENV:Body>\r\n',
 '<m:', action, ' xmlns:m="', svc, '">\r\n');

 foreach f (keys(fields))
 {
   xml = strcat(xml, '<', f, '>', fields[f], '</', f, '>\r\n');
 }
 xml = strcat(xml, '</m:', action, '>\r\n',
'</SOAP-ENV:Body>\r\n',
'</SOAP-ENV:Envelope>\r\n' );
 return xml;
}

function upnp_make_soap_req(port, url, action, svc, fields)
{
  local_var xml, rq;

  xml = upnp_make_soap_data(action: action, fields: fields, svc: svc);
  rq = http_mk_post_req(port: port, item: url, data: xml, host: get_host_ip(),
     add_headers: make_array('Content-Type', 'text/xml', 
    'SOAPAction', strcat('"', svc, '#', action, '"')) );
  rq['User-Agent'] = NULL;
  rq['Connection'] = NULL;
  rq['Pragma'] = NULL;
  rq['Accept'] = NULL;
  rq['Accept-Language'] = NULL;
  rq['Accept-Charset'] = NULL;
  rq['Cookie'] = NULL;
  rq['Date'] = NULL;
  return rq;
}


# Local Variables: **
# mode:Fundamental **
# comment-column:0 **
# comment-start: "# "  **
# End: **
