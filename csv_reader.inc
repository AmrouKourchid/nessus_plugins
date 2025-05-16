#TRUSTED 2139a58aa802c97eefb3aaba0f9c3f1f1219b093e1e287fa4a46f63e7144dc8ba4274d93ab7baab8d46c84ed85446cf28a579ce17d40d3c0cfc9abf00f2ee3bfc0680ec8eb4a6f260cfd74be3baf04cf6ba7cbde25f07e3100cfe980bbf9a591c9d91d2b450134c5836b516f07e947d68995cf5e596ad78b3cfd9b580ce2765703ecc1c282833a823f1611d890fa11ee6c602e6657590552fe433efc157eef1dc0aa2d047ec6118053124791b3da73ccbf5e4ca349ba5d912ad82b9d6cc2d3c8866bee4a7a021528dd8d9ef86309c90f377db5dee1ac0640d1f9a13308e703b8e64b89fd16c5c2e15cad13172a95f2b4835c936c8ef5576558de5ebeeed4128c8e4c5bd29f7137944a5c7b368d2eaac011bff7d06d356df6317307b798e3688af45e2bc7a4891575077de05e8e81e0eda22de6de4697e47e435aea0aa2f95ed46d2ae713b530cd49bb105ff2949724d3dbee0071bf19d59bf2936110cc5590545eb9bd13eaa3e65c6bbe0be739cdcdd4c8cc3eebc743992e07479e400951fa54d421ab08ce984d9a52e14beb0a86ef49c3ede34c18c764895492c35ebd95ffb2a5e85b5cae2441e6a067867d9404fd9d063a85fb40b7f95848381ff8408ec82ac19820702af09a6132ac2f0c1b4effdcfdf86e3bbd93708b9dd6f34d5505db776c84bff8d51bf3a00881ac29d6fa94ee448ff33926ed4e55015dd94aaee49882
#TRUST-RSA-SHA256 5bcfd17c580b1dd0bbc4b1f5aa6bc8615d96d8d9b4dbf60934900baa56b8f4e3793cb7e1496268fedd09ff5655e3f0273a9dd4355bb2be3c17f29979b780eba7c64df301ff4d96bad0c47f2e2688c24fc6828f0b156b0e8509c5af9d3dd970715914e269dad710256a50a3b9cf8624d9395badf45515a80dcbfeaed540c0eaf03bd1d9479a04614a36d4b934a8018b99f39c80392e8f182a97b8ac071d35049b5be02157637db0a3f83a5826bec82d1bd43be9d42ba8f0fb31a04db3cf689fbf3975ba98cfe0c7d64f18cd91c213ab4e123fc510b66d41345dd6431d3c24603566065208606637eb8775b6d4d0008af8de80364cb5f83f344aa4bf631a2ed1b184c5f683a2e5ccd7ecb6ed108bacf2a0f372387769df357af6f62d658f8515eaa3799ce0569d9ac44d6f4dfa88654c145e1bb1c40edf3b79d05f5c261f9fa04afffdd2925af975c860dcf1132458250e3d024558bca8bda85e76b22486071deb2d06dc45707b21c9505bc78b8f87ae148b781c8a265db1ada1654f7a5d4dbea75d82b3e15e9eb523588c75ec6e52f66e40ed68a2e179ca5de7d66a312ae101e650127862869adec1055a56f0e24590c481ef002dbca99c020c4044dab27f4ca634d85b1c4ba5fac7cdfcc66a78f0f3c63136332377704a665c2b42e0c97dad642bbb7b44ed378f9978fed7a6b81a0bb026bce905af2b5aba1fb78085427a28b2
###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# csv_reader.inc
#
# Revision: 1.5
###

include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");

object csv_reader
{
  var csv, data_records;

  ##
  # Constructor
  #
  # @anonparam CSV content
  ##
  function csv_reader()
  {
    csv = _FCT_ANON_ARGS[0];
  }

  ##
  # Parse and validate CSV
  #
  # @param [fields:list] field names
  # @param [optional_fields:list] optional fields that are allowed to be empty (optional)
  # @param [validation:array] field names as keys with regular expressions as values used for validation (optional)
  #
  # @remark if 'num_req_fields' is omitted, the max index of 'fields' parameter is used
  # @remark 'data_records' member variable is updated with list of arrays of data records from CSV
  #
  # @return TRUE if CSV is successfully parsed,
  #         NULL if an error occurs
  ##
  public function parse_csv(fields, optional_fields, validation)
  {
    var lines, data_record, field, values, log_prefix, log_message, value, i, j, line_num, column_num;
    var num_req_fields, optional_field, optional_field_matched, failed_validation;

    if (empty_or_null(csv))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "CSV content is empty or NULL.");
      return NULL;
    }

    if (empty_or_null(fields))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing 'fields' parameter.");
      return NULL;
    }

    # Number of required fields
    num_req_fields = max_index(fields);
    if (!empty_or_null(optional_fields))
      num_req_fields = num_req_fields - max_index(optional_fields);

    data_records = [];

    # Remove Byte Order Mark (BOM)
    if (substr(csv, 0, 2) == '\xef\xbb\xbf')
    {
      csv = str_replace(string:csv, find:'\xef\xbb\xbf', replace:'', count:1);
    }

    # Iterate over each line
    #  Note: instead of breaking out of the loops when the first error occurs,
    #  collect all issues to be more informative for the user
    lines = split(csv, keep:FALSE);

    for (i = 0; i < max_index(lines); i++)
    {
      line_num = i + 1;

      values = split(lines[i], sep:',', keep:FALSE);

      if (empty_or_null(values))
      {
        dbg::detailed_log(
          lvl: 3,
          src: FUNCTION_NAME,
          msg: "Empty line",
          msg_details: {
            "Line number": {"lvl": 3, "value": line_num}});
        continue;
      }

      if (max_index(values) < num_req_fields)
      {
        dbg::detailed_log(
          lvl: 2,
          src: FUNCTION_NAME,
          msg: "The number of values is less than the expected number of fields",
          msg_details: {
            "Line number": {"lvl": 2, "value": line_num},
            "Number of values": {"lvl": 2, "value": max_index(values)},
            "Number required": {"lvl": 2, "value": num_req_fields}});
        continue;
      }

      # Iterate fields and assign simply based on position
      data_record = {};
      failed_validation = false;

      for (j = 0; j < max_index(fields); j++)
      {
        column_num = i + 1;

        field = fields[j];
        value = trim(values[j]);

        optional_field_matched = false;

        log_prefix = strcat('Line ', line_num, ', Column ', column_num, ' (', field, '): ');

        if (empty_or_null(value))
        {
          foreach optional_field (optional_fields)
          {
            # If field is optional and empty
            if (field == optional_field)
            {
              optional_field_matched = true;
              break;
            }
          }

          if (!optional_field_matched)
            dbg::detailed_log(
              lvl: 2,
              src: FUNCTION_NAME,
              msg: "Field is empty.",
              msg_details: {
                "Info": {"lvl": 2, "value": log_prefix}});
        }

        # Validation
        if (!empty_or_null(validation[field]) && !optional_field_matched)
        {
          if (value !~ validation[field])
          {
            if (field =~ 'password')
            {
              dbg::detailed_log(
                lvl: 1,
                src: FUNCTION_NAME,
                msg: "Value failed validation.",
                msg_details: {
                  "Info": {"lvl": 1, "value": log_prefix}});
            }
            else
            {
              dbg::detailed_log(
                lvl: 1,
                src: FUNCTION_NAME,
                msg: "Value failed validation.",
                msg_details: {
                  "Info": {"lvl": 1, "value": log_prefix},
                  "Value": {"lvl": 3, "value": value}});
            }

            failed_validation = true;

            continue;
          }
        }

        # Value is valid
        data_record[field] = value;
      }

      # Only add data record if all values validated properly
      if (!failed_validation)
        append_element(var:data_records, value:data_record);
      else
        dbg::detailed_log(
          lvl: 1,
          src: FUNCTION_NAME,
          msg: "Line failed validation.",
          msg_details: {
            "Line number": {"lvl": 1, "value": line_num}});
    }

    return TRUE;
  }
}
