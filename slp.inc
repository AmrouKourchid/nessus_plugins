#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# slp.inc
#
# Revision: 1.06 $
#

# Functions for the Service Location Protocol (SLP) protocol.

include("compat_shared.inc");
include("byte_func.inc");
include('install_func.inc');
include('resolv_func.inc');
include('debug.inc');
include('data_protection.inc');

namespace slp
{
  var SLP_ATTR_LIMIT = 25;
  var SLP_ATTR_LIST_LEN_LIMIT = 1024;

  # Function Types
  var SLP_FUNCT_SRVRQST        = 1;
  var SLP_FUNCT_SRVRPLY        = 2;
  var SLP_FUNCT_SRVREG         = 3;
  var SLP_FUNCT_SRVDEREG       = 4;
  var SLP_FUNCT_SRVACK         = 5;
  var SLP_FUNCT_ATTRRQST       = 6;
  var SLP_FUNCT_ATTRRPLY       = 7;
  var SLP_FUNCT_DAADVERT       = 8;
  var SLP_FUNCT_SRVTYPERQST    = 9;
  var SLP_FUNCT_SRVTYPERPLY    = 10;
  var SLP_FUNCT_SAADVERT       = 11;

  var SVC_TYPES = [
    'service:service-agent',
    'service:directory-agent'
  ];

  function mk_SLPFindSrv_req(flags, svc, pktlen, nxo, xid, lang, prlist, scope, pred, slp_spi)
  {
    if (empty_or_null(flags)) flags = 0;
    if (empty_or_null(nxo)) nxo = 0;     # 0 => no extensions being used
    if (empty_or_null(xid)) xid = rand() % 0xffff;
    if (empty_or_null(lang)) lang = 'en';
    if (empty_or_null(prlist)) prlist = '';
    if (empty_or_null(scope)) scope = 'DEFAULT';
    if (empty_or_null(pred)) pred = '';
    if (empty_or_null(slp_spi)) slp_spi = '';
    
    pktlen = 24 + strlen(lang+prlist+svc+scope+pred+slp_spi);
    var pkt = mkbyte(2) +                # version (nb: no support for version 1)
      mkbyte(SLP_FUNCT_SRVRQST) +          # function (1 => service request)
      mkbyte(pktlen / 255) +             # packet length
        mkword(pktlen % 255) +
      mkword(flags) +                    # flags
      mkbyte(nxo / 255) +                # next extension offset
        mkword(nxo % 255) +
      mkword(xid) +                      # XID
      mkword(strlen(lang)) + lang +      # language tag
      mkword(strlen(prlist)) + prlist +  # previous responder list
      mkword(strlen(svc)) + svc +        # service type
      mkword(strlen(scope)) + scope +    # scope list
      mkword(strlen(pred)) + pred +      # predicate
      mkword(strlen(slp_spi)) + slp_spi; # SLP SPI

    return pkt;
  }

  function mk_SLPFindSrvType_req(flags, svc, pktlen, nxo, xid, lang, prlist, scope, pred, slp_spi)
  {
    #TODO
    if (empty_or_null(flags)) flags = 0;
    if (empty_or_null(nxo)) nxo = 0;     # 0 => no extensions being used
    if (empty_or_null(xid)) xid = rand() % 0xffff;
    if (empty_or_null(lang)) lang = 'en';
    if (empty_or_null(prlist)) prlist = '';
    if (empty_or_null(scope)) scope = 'DEFAULT';
    if (empty_or_null(pred)) pred = '';
    if (empty_or_null(slp_spi)) slp_spi = '';
    
    pktlen = 20 + strlen(lang+prlist+scope);
    var pkt = mkbyte(2) +                # version (nb: no support for version 1)
      mkbyte(SLP_FUNCT_SRVTYPERQST) +     # function (9 => service type request)
      mkbyte(pktlen / 255) +             # packet length
        mkword(pktlen % 255) +
      mkword(flags) +                    # flags
      mkbyte(nxo / 255) +                # next extension offset
        mkword(nxo % 255) +
      mkword(xid) +                      # XID
      mkword(strlen(lang)) + lang +      # language tag
      mkword(strlen(prlist)) + prlist +  # previous responder list
      mkword(0xffff) +                   # naming authority (0xffff => omitted)
      mkword(strlen(scope)) + scope;     # scope list

    return pkt;
  }

  function mk_SLPFindAttrs_req(flags, svc_url, pktlen, nxo, xid, lang, prlist, scope, taglist, slp_spi)
  {
    if (empty_or_null(flags)) flags = 0;
    if (empty_or_null(nxo)) nxo = 0;     # 0 => no extensions being used
    if (empty_or_null(xid)) xid = rand() % 0xffff;
    if (empty_or_null(lang)) lang = 'en';
    if (empty_or_null(prlist)) prlist = '';
    if (empty_or_null(scope)) scope = 'DEFAULT';
    if (empty_or_null(taglist)) taglist = '';
    if (empty_or_null(slp_spi)) slp_spi = '';
    
    pktlen = 24 + strlen(lang+prlist+svc_url+scope+taglist+slp_spi);
    var pkt = mkbyte(2) +                # version (nb: no support for version 1)
      mkbyte(SLP_FUNCT_ATTRRQST) +        # function (6 => attribute request)
      mkbyte(pktlen / 255) +             # packet length
        mkword(pktlen % 255) +
      mkword(flags) +                    # flags
      mkbyte(nxo / 255) +                # next extension offset
        mkword(nxo % 255) +
      mkword(xid) +                      # XID
      mkword(strlen(lang)) + lang +      # language tag
      mkword(strlen(prlist)) + prlist +  # previous responder list
      mkword(strlen(svc_url)) + svc_url +        # service URL
      mkword(strlen(scope)) + scope +    # scope list
      mkword(strlen(taglist)) + taglist +      # tag list
      mkword(strlen(slp_spi)) + slp_spi; # SLP SPI

    return pkt;
  }

  # attr_list = (product="VMware ESXi 6.5.0 build-4564106"),(hardwareUuid="4226BF9F-34FF-C2E3-F70E-FED4245F5577")
  # 1683053614 1 SLP/svc/service:VMwareInfrastructure=(product="VMware ESXi 6.5.0 build-4564106"),(hardwareUuid="4226BF9F-34FF-C2E3-F70E-FED4245F5577")
  # 1683053614 1 SLP/svc=service:VMwareInfrastructure
  function slp_parse_attributes(attr_list)
  {
    var parsed_attrs = {};
    if (empty_or_null(object: attr_list))
      return parsed_attrs;

    var splits;
    foreach (var attr in split(keep: FALSE, sep: ',', attr_list))
    {
      attr = attributes_strip_parens(attr:attr);
      splits = split(keep: FALSE, sep: '=', attr);
      parsed_attrs[splits[0]] = splits[1];
    }

    return parsed_attrs;
  }

  function attributes_strip_parens(attr)
  {
    if (substr_at_offset(str: attr, blob: '(', offset: 0))
      attr = substr(attr, 1, strlen(attr));
    if (substr_at_offset(str: attr, blob: ')', offset: strlen(attr)-1))
      attr = substr(attr, 0, strlen(attr)-2);
    return attr;
  }

  ##
  # Occasionally, SLP will store a result for another host. We should make note of it
  # This func will save it to the kb.
  #
  # @param  string   ip           REQUIRED ip address found (that doesn't match the scan target)
  # @param  string   script_name  REQUIRED The plugin name that identified the SLP data.
  ##
  function store_discovered_ip(ip, script_name)
  {
    var discovered_ips_key = "Host/AdjacentHosts/DiscoveredIPs";
    var discovered_ips = {};
    discovered_ips = get_one_kb_item(discovered_ips_key);
    if (!empty_or_null(object: discovered_ips))
      discovered_ips = deserialize(discovered_ips);
    discovered_ips[script_name] = [ip];
    replace_kb_item(name: discovered_ips_key, value: serialize(discovered_ips));
  }


  ##
  # Process a list of SLP attributes from the KB, pull out relevant attributes
  # from a list, and return them as extra or extra_no_report
  #
  # @param  array   slp_attributes    REQUIRED Array TODO
  # @param  array   slp_kb_attrs      REQUIRED Array TODO
  # @param  string  slp_kb_svc_prefix REQUIRED The SLP kb prefix including the service 
  #
  # @return array   Returns an array containing extra and extra_no_report for report_install()
  ##
  function parse_slp_kb_attributes(slp_attributes, slp_kb_attrs, slp_kb_svc_prefix)
  {
    var extra = {};
    var extra_no_report = {};
    for (var key in slp_attributes)
    {
      if (!empty_or_null(object: slp_kb_attrs[slp_kb_svc_prefix + key] ))
      {
        switch(slp_attributes[key].type)
        {
          case 'e':
            extra[slp_attributes[key].name] = slp_kb_attrs[slp_kb_svc_prefix + key];
            continue;
          case 'es':
            # sanitize no matter what. if there's need, we can change to sanitize just name/email/whatever
            if (!data_protection::is_sanitize_enabled(flag:data_protection::DPKB_ENABLED))
              extra[slp_attributes[key].name] = slp_kb_attrs[slp_kb_svc_prefix + key];
            continue;
          case 'enr':
            extra_no_report[slp_attributes[key].name] = slp_kb_attrs[slp_kb_svc_prefix + key];
            continue;
          case 'n':
            continue;
          default:
            continue;
        }
      }
    }
    return {'extra':extra, 'extra_no_report': extra_no_report};
  }

  # Functions related to processing of SLP information for the detection of
  # Storage Devices (SANs)
  namespace san
  {
    var slp_storage_svc_prefixes = 
    [
      'service:api:http',
      'service:api:https',
      'service:ui:telnet',
      'service:ui:ssh',
      'service:firmware-update:ftp',
      'service:firmware-update:sftp',
      'service:api:snmp'
    ];

    var slp_storage_attributes = 
    {
      'x-system-name'                      : {'name' : 'Hostname',   'type' : 'n'  },   #	system-name               # hostname
      'x-system-contact'                   : {'name' : 'Contact',    'type' : 'es'  },   #	system-contact
      'x-system-location'                  : {'name' : 'Location',   'type' : 'es'  },   #	system-location
      'x-system-information'               : {'name' : 'Sys Info',   'type' : 'n'  },   #	system-information
      'x-midplane-serial-number'           : {'name' : 'Serial',     'type' : 'enr'},   #	midplane-serial-number
      'x-vendor-name'                      : {'name' : 'Vendor',     'type' : 'e'  },   #	vendor-name               # vendor
      'x-product-id'                       : {'name' : 'Model',      'type' : 'e'  },   #	product-id                # model
      'x-product-brand'                    : {'name' : 'Product',    'type' : 'e'  },   #	product-brand             # family
      'x-wwnn'                             : {'name' : 'WWNN',       'type' : 'n'  },   #	current-node-wwn
      'x-platform-type'                    : {'name' : 'Platform',   'type' : 'enr'},   #	platform-type
      'x-bundle-version'                   : {'name' : 'Version',    'type' : 'e'  },   #	no corresponding property # version
      'x-build-date'                       : {'name' : 'Build Date', 'type' : 'enr'},   #	no corresponding property
      'x-mac-address'                      : {'name' : 'MAC',        'type' : 'enr'},   #	no corresponding property
      'x-top-level-assembly-part-number'   : {'name' : 'Part',       'type' : 'n'  },   #	no corresponding property
      'x-top-level-assembly-serial-number' : {'name' : 'Serial',     'type' : 'n'  }    #	no corresponding property
    };


    ##
    # Check a list of vendor/product pairs for matching SLP entries. Report if found.
    # This function audits AND can return NULL.
    # This function calls register_install() but expects the calling plugin to check
    # the return value and call report_install() iff. appropriate.
    #
    # @param  array   devices   REQUIRED List of Arrays with keys: 'vendor' and 'product'
    # @param  int     port      REQUIRED The port discovered. s/b 427.
    #
    # @return array   Returns an array containing extra and extra_no_report for report_install()
    ##
    function detect_storage_device(devices, port)
    {
      if (empty_or_null(object: devices))
        return NULL;
      
      if (empty_or_null(object: port ))
        port = 427;

      # check storage services
      # the services should share similar info on the same host
      # they may not, but if it becomes an issue we can change.
      var storage_attrs = NULL;
      var slp_kb_svc_prefix;
      foreach (var svc in slp_storage_svc_prefixes)
      {
        slp_kb_svc_prefix = 'SLP/svc/' + svc + '/';
        storage_attrs = get_kb_list(slp_kb_svc_prefix + '*');
        if (!empty_or_null(storage_attrs))
          break;
        continue;
      }

      if (empty_or_null(storage_attrs))
        return NULL;

      var report = slp::parse_slp_kb_attributes(slp_attributes:slp::san::slp_storage_attributes, slp_kb_attrs:storage_attrs, slp_kb_svc_prefix:slp_kb_svc_prefix);

      var vendor, product;
      foreach (var device in devices)
      {
        vendor = device.vendor;
        product = device.product;

        if (empty_or_null(object: vendor) || empty_or_null(object: product))
          continue;

        if (empty_or_null(object:report.extra.Vendor))
          audit(AUDIT_HOST_NOT, 'a '+vendor+' device');

        if (empty_or_null(object:report.extra.Product))
          audit(AUDIT_HOST_NOT, 'a '+product+' device');

        if (report.extra.Vendor == "Dot Hill Systems")
        {
          report.extra.Vendor = "Seagate";
          if (report.extra.Product == 'Dot Hill' && report.extra.Model =~ '^AssuredSAN')
            report.extra.Product = 'AssuredSAN';
        }

        if (report.extra.Vendor == 'DELL EMC' && report.extra.Version =~ "^ME\d\.\d\.\d\.\d\.\d$")
          report.extra.Product = "PowerVault";

        if (tolower(report.extra.Vendor) != tolower(vendor))
          continue;
        
        if (tolower(report.extra.Product) == tolower(product))
          break;
      }
      if (tolower(report.extra.Vendor) != tolower(vendor) || tolower(report.extra.Product) != tolower(product))
        audit(AUDIT_HOST_NOT, 'a '+vendor+' '+product+' device');

      var ip;
      if (!empty_or_null(object: storage_attrs[slp_kb_svc_prefix + 'x-ip-addresses'] ))
        ip = storage_attrs[slp_kb_svc_prefix + 'x-ip-addresses'];
      else
        audit(AUDIT_NOT_DETECT, "A SAN", port);

      dbg::detailed_log(lvl:1, msg:"found ip: "+ip);

      var app_name = vendor + ' ' + product;
      if (is_same_host(a: ip) == 1)
      {
        replace_kb_item(name:'SLP/storage_device', value:app_name);
        register_install(
          app_name:app_name,
          service:'SLP',
          port:port,
          vendor: report.extra.Vendor,
          product: report.extra.Product,
          version: report.extra.Version,
          extra: report.extra,
          extra_no_report: report.extra_no_report
        );

        return app_name;
      }
      else
      {
        slp::store_discovered_ip(ip:ip, script_name:SCRIPT_NAME);
        audit(AUDIT_NOT_DETECT, app_name, port);
      }
    }
  }
}
