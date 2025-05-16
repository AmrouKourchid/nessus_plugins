#TRUSTED 5c6d2021742f0cfe784e6293273e5788d8f87690401f19fd4b2cae926903396f34c47c7218409a31af016efb528ffca406b4e80d53e579105982f00116814fe6e39a47c58ef8400e7371c9cb2b069e16a32ed499fc13faa598ccef42704118997380419fb40767ef41caac631be3f44bcd8a230911f10fbe9676d845efa51f8f20676082eda0ccfbdbffe46052aa345b5b78101865c82f8a530f8bb4d8b36f4f3e2b90db3b68e28d0e88400a844d49616871bd84e8058b7450466b8e9278bd2d5151e1eff945b8818abe8fb9809c49e8f5a2468727b8f51d138c14580ceedde4852cd4643b5975da46cddc5e6dbd874cb221a796288ff0dc39c7fc871d9bda0e213f53983b5be96f94e18d17047cd43dd0f06f3216fcf1f8d6919d5a0ac8e3ba0d73c6127ef68b22cf9b083b07284ef81319e4bda5dec4db6c0e162fbdcbbe082aba5d60d5e0a7275dbd23d52fda5e3ca67f420ac1f5c33bf67f631cff0a96052412b340c67d73fb4cc31d8137cd00fd93b179f9c45247d43bcb985a94ecad7255e0b8f7f1a630e6cbfc34f17b54270cb89b956081dc8f9367f1c7205ac33b4f501e9993ed97a0bbdb12a77375ddcc70061919c4949c27fe37de21851b2a70173ef5e1e97316ef70497f18c2e503fd398844270159d8006299bc151d320c8f333ac578fe9b7ef7719875f1973a690a43f699e6c4d8cb033448a8f287b2da6c3c
#TRUST-RSA-SHA256 83eaacfd8388a2935657f536800a8b1902056c94769de2e6f70484bcaf3d7df13fb7337cc809855968b11380f2e93e51bcd232ce22f49d7c63a6ff0895da7a6ba5e5a7304cef1648fcdf62492c8c4ebcc03a0ecc91e6b4b6282d2946f48bd9dd6d8b455b9b9efd12c55e4e9e0674cfee9c3c648732d2dca450d1ef9169ebb4d2df3a1438157204a6dac6f50a639c9e3e193c4d73bc1c124cc471bea3109ba3da65d32c636273567f2fba552d7fe87514b60c81e04822103e6c5091433333c90d2932de2b834445cfa38d660e2dbe7f2bf63871828f1cc69b6c6dddf97c419563e17d097624071b9a5c27a72e2f9f2ac786e3ad9f21386461bcf67973f68f1813fa0d6a729b7ffac38e4f6192c3b5be0cc8090787606e1b59bcba43c217d180886f4a612dd4a8f61ba7a8a4778077899c3e7e63d7c05146036eccf6f19da3f281d1be12c8f937d9201c6d85c3b557316c00ca330e7774b8551df4150276b10552138f9189af5663fd96163742a6de887e558b86b883b2392d5199bd3f4ee660c401b7bcfe939b07168419067167bcc586a3cfa58047048be447c0f1368e977484b3e04b2312b85ea669d1fc5b0f36f0de130f7e42f0ac95f753e619c03d4f5331ccb625b4ff5c8fd101cf935ecebdfdce82038943bb55fca669482f13054ea02e38cb6e954af8a6140b025f32550f0ef2095a1a6207e17eeb906e2f701f17b9c8
###
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# #include misc_func.inc
# #include spad_log_func.inc
# 
# amazon_aws_ami.inc
# Revision: 1.12
###

include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");
include("agent.inc");

global_var AWS_AMI_API_ROOT, AWS_AMI_API_HOST, AWS_AMI_API_ITEMS, AWS_AMI_HOST_TAG_BASE, AWS_AMI_KB_BASE;
global_var AWS_AMI_IMDSV2_TOKEN_URI, AWS_IMDSV2_TOKEN_PUT_REQUEST_HEADER, AWS_IMDSV2_TOKEN_HEADER, AWS_AMI_API_ENDPOINT;
global_var AWS_AMI_IMDSV2_TOKEN_ENDPOINT, AWS_AMI_INSTANCE_IDENTITY_DOCUMENT_ENDPOINT, AWS_AMI_API_INSTANCE_IDENTITY_DOCUMENT, api_get_item, AWS_AMI_METADATA_ENDPOINT;
global_var AWS_AMI_IMDSV2_TOKEN_PUT_REQUEST_HEADER;

##
# AMI API Host
##
AWS_AMI_API_HOST = "169.254.169.254";

##
# AMI API Endpoint
##
AWS_AMI_API_ENDPOINT = 'http://' + AWS_AMI_API_HOST;

##
# AMI API Root
##
AWS_AMI_API_ROOT  = "/latest/meta-data/";

##
# AMI METADATA ENDPOINT
##
AWS_AMI_METADATA_ENDPOINT = AWS_AMI_API_ENDPOINT + AWS_AMI_API_ROOT;

##
# IMDS v2 Token URI
##
AWS_AMI_IMDSV2_TOKEN_URI = "/latest/api/token";

##
# IMDS v2 Token ENDPOINT
##
AWS_AMI_IMDSV2_TOKEN_ENDPOINT = AWS_AMI_API_ENDPOINT + AWS_AMI_IMDSV2_TOKEN_URI;

##
# IMDS v2 Token PUT Request Header
##
AWS_AMI_IMDSV2_TOKEN_PUT_REQUEST_HEADER = "X-aws-ec2-metadata-token-ttl-seconds: 21600";

##
# AMI Instance Identity Document URI
##
AWS_AMI_API_INSTANCE_IDENTITY_DOCUMENT = '/latest/dynamic/instance-identity/document';

##
# AMI Instance Identity Document Endpoint
##
AWS_AMI_INSTANCE_IDENTITY_DOCUMENT_ENDPOINT = AWS_AMI_API_ENDPOINT + AWS_AMI_API_INSTANCE_IDENTITY_DOCUMENT;

##
# XML Host Tag base
##
AWS_AMI_HOST_TAG_BASE = "aws-instance";

##
# KB Base
##
AWS_AMI_KB_BASE = "Host/AWS/AMI";

##
# API Items with their validation regular expressions
##
AWS_AMI_API_ITEMS = make_array(
  'ami-id'                      , "^ami-[A-Za-z0-9]+$",
  'instance-id'                 , "^i-[A-Za-z0-9]+$",
  'hostname'                    , "^[A-Za-z\-0-9.]+$",
  'local-hostname'              , "^[A-Za-z\-0-9.]+$",
  'public-hostname'             , "^[A-Za-z\-0-9.]+$",
  'local-ipv4'                  , "^\d+\.\d+\.\d+\.\d+$",
  'public-ipv4'                 , "^\d+\.\d+\.\d+\.\d+$",
  'mac'                         , "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",
  'block-device-mapping'        , "ami"
);

##
# Discrepancy check of the IP addresses from API responses to collected IP addresses
# to flag the response as potentially coming from a proxy server
#
# @param [apiresults:array] Instance metadata successfully gathered
# @param [ipv4_addresses:list] IPv4 addresses gathered from plugins
#
# @return true if IP address matched; false if the IP address did not match;  NULL otherwise
##
function ip_address_check(apiresults, ipv4_addresses)
{
  var ipv4_address, ipv4_api_items, ipv4_api_item;
  var api_item_found = false;

  # Parameter checks
  if (empty_or_null(apiresults))
  {
    err_print('Missing "apiresults" parameter.');
    return NULL;
  }

  # Require this parameter since the API requests may be from an IP address
  # other than the IP address scanned
  if (empty_or_null(ipv4_addresses))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing IPv4 addresses.");
    return NULL;
  }

  # Additional IP address - should always render a valid IP address
  if (agent())
  {
    ipv4_address = agent_get_ip();
    if (!empty_or_null(ipv4_address))
      ipv4_addresses = make_list(ipv4_addresses, ipv4_address);
  }
  else
  {
    ipv4_address = get_host_ip();
    if (!empty_or_null(ipv4_address))
      ipv4_addresses = make_list(ipv4_addresses, ipv4_address);
  }
  dbg::detailed_log(
    lvl: 3,
    src: FUNCTION_NAME,
    msg: "IPv4 addresses found",
    msg_details: {
      "Addresses": {"lvl": 3, "value": join(ipv4_addresses,sep: ', ')}});
  # Process IPv4 addresses
  ipv4_api_items = [ 'local-ipv4', 'public-ipv4', 'privateIp', 'publicIp' ];

  foreach ipv4_address (list_uniq(ipv4_addresses))
  {
    if (ipv4_address == "127.0.0.1")
      continue;

    foreach ipv4_api_item (ipv4_api_items)
    {
      if (empty_or_null(apiresults[ipv4_api_item]))
        continue;
    
      if (apiresults[ipv4_api_item] !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
      {
        dbg::detailed_log(
          lvl: 1,
          src: FUNCTION_NAME,
          msg: "Unexpected IP address",
          msg_details: {
            "API Result": {"lvl": 1, "value": apiresults[ipv4_api_item]},
            "API Item": {"lvl": 1, "value": ipv4_api_item}});
        continue;
      }
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "API item found",
        msg_details: {
          "API Item": {"lvl": 2, "value": ipv4_api_item}});
      api_item_found = true;

      if (ipv4_address == apiresults[ipv4_api_item])
      {
        dbg::detailed_log(
          lvl: 2,
          src: FUNCTION_NAME,
          msg: "IPv4 address matched.",
          msg_details: {
            "Address": {"lvl": 2, "value": ipv4_address}});
        return true;
      }
    }
  }

  if (!api_item_found)
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "None of IP address API items were returned from the metadata queries.");
    return NULL;
  }
  dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "None of the IP addresses matched indicative that the metadata came from a proxy server.");
  return false;
}

##
# Process and save the block-device-mapping metadata
#
# @param [data:string] Data returned from block-device-mapping API to parse
# @param [success:list reference] List tracking succesfull data retrieved from the API. Will be updated with additional data.
# @param [apiresults:array reference] Array to save data from successful API requests. Will be updated with additional data.
# @param [api_get_item:function reference] Function reference to function to make addtional API calls.
#
# @return NULL
##
function process_block_device_mapping_data(data, &success, &apiresults, api_get_item)
{
  var apitem = 'block-device-mapping';
  var disk_count = make_array();
  foreach var line (split(data, keep:FALSE))
  {
    # Only make requests for the APIs we are interested in
    var match = pregmatch(pattern:"^(ami|root|swap|ebs|ephemeral)\d*$", string:line);
    if (!empty_or_null(match))
    {
      var device = api_get_item(apitem + "/" + line);
      if (!empty_or_null(device))
      {
        if (isnull(disk_count[match[1]]))
        {
          disk_count[match[1]] = 1;
        }
        else
        {
          disk_count[match[1]]++;
        }
        apiresults[apitem + "-" + line] = device;
        append_element(var:success, value:apitem + "-" + line);
      }
    }
  }

  # Save the EBS and Ephemeral disk counts.
  # Other disk types will be a max of 1 making a seperate count less useful.
  append_element(var:success, value:apitem + "-" + "ebs-count");
  var ebs_count = "0";
  if (!isnull(disk_count["ebs"]))
  {
    ebs_count = string(disk_count["ebs"]);
  }
  apiresults[apitem + "-" + "ebs-count"] = ebs_count;

  append_element(var:success, value:apitem + "-" + "ephemeral-count");
  var ephemeral_count = "0";
  if (!isnull(disk_count["ephemeral"]))
  {
    ephemeral_count = string(disk_count["ephemeral"]);
  }
  apiresults[apitem + "-" + "ephemeral-count"] = ephemeral_count;
}
