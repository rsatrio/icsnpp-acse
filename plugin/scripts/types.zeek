#THIS CODE IS GENERATED. DON'T CHANGE MANUALLY!
module acse;
export {

  # ======== PRIMITIVE TYPES =======
  type ASO_context_name: string;

  type AP_title_form2: string;

  type AP_title_form3: string;

  type ASO_qualifier_form2: int;

  type ASO_qualifier_form3: string;

  type ASO_qualifier_form_octets: string;

  type AP_invocation_identifier: int;

  type AE_invocation_identifier: int;

  type Mechanism_name: string;

  type Implementation_data: string;

  type Presentation_context_identifier: int;

  type Abstract_syntax_name: string;

  type TransferSyntaxName: string;

  type ASOI_identifier: int;

  type Associate_result: enum {
    accepted = 0,
    rejected_permanent = 1,
    rejected_transient = 2,
  };

  type Result: enum {
    acceptance = 0,
    user_rejection = 1,
    provider_rejection = 2,
  };

  type Release_request_reason: enum {
    Release_request_reason_normal = 0,
    urgent = 1,
    Release_request_reason_user_defined = 30,
  };

  type Release_response_reason: enum {
    Release_response_reason_normal = 0,
    not_finished = 1,
    Release_response_reason_user_defined = 30,
  };

  type ABRT_source: enum {
    service_user = 0,
    service_provider = 1,
  };

  type ABRT_diagnostic: enum {
    ABRT_diagnostic_no_reason_given = 1,
    protocol_error = 2,
    ABRT_diagnostic_authentication_mechanism_name_not_recognized = 3,
    ABRT_diagnostic_authentication_mechanism_name_required = 4,
    ABRT_diagnostic_authentication_failure = 5,
    ABRT_diagnostic_authentication_required = 6,
  };

  type Simply_encoded_data: string;

  type AE_title_form2: string;


  # ======== COMPLEX TYPES =======
  type Context: record {
    contextType: string;
    contextValues: vector of string;
    fallback: bool;
  };

  type AttributeTypeAndDistinguishedValue: record {
    _type: string;
    value: string;
    primaryDistinguished: bool;
    valuesWithContext: vector of record {
      distingAttrValue: string &optional;
      contextList: vector of Context &optional;
    } &optional;
  };

  type RelativeDistinguishedName: vector of AttributeTypeAndDistinguishedValue;

  type Name: record {
    rdnSequence: vector of RelativeDistinguishedName &optional;
  };

  type EXTERNALt: record {
    direct_reference: string &optional;
    indirect_reference: int &optional;
    data_value_descriptor: string &optional;
    encoding: record {
      single_ASN1_type: string &optional;
      octet_aligned: string &optional;
      arbitrary: string &optional;
    } &optional;
  };

  type AP_title_form1: Name;

  type AP_title: record {
    ap_title_form1: AP_title_form1 &optional;
    ap_title_form2: AP_title_form2 &optional;
    ap_title_form3: AP_title_form3 &optional;
  };

  type ASO_qualifier_form1: RelativeDistinguishedName;

  type ASO_qualifier: record {
    aso_qualifier_form1: ASO_qualifier_form1 &optional;
    aso_qualifier_form2: ASO_qualifier_form2 &optional;
    aso_qualifier_form3: ASO_qualifier_form3 &optional;
    aso_qualifier_form_any_octets: ASO_qualifier_form_octets &optional;
  };

  type AE_qualifier: ASO_qualifier;

  type ACSE_requirements: vector of enum {
    authentication,
    aSO_context_negotiation,
    higher_level_association,
    nested_association,
  };

  type Authentication_value_other: record {
    other_mechanism_name: string;
    other_mechanism_value: string;
  };

  type Authentication_value: record {
    charstring: string &optional;
    bitstring: string &optional;
    external: EXTERNALt &optional;
    other: Authentication_value_other &optional;
  };

  type ASO_context_name_list: vector of ASO_context_name;

  type Context_list: vector of record {
    pci: Presentation_context_identifier;
    abstract_syntax: Abstract_syntax_name;
    transfer_syntaxes: vector of TransferSyntaxName;
  };

  type Default_Context_List: vector of record {
    abstract_syntax_name: Abstract_syntax_name &optional;
    transfer_syntax_name: TransferSyntaxName &optional;
  };

  type Syntactic_context_list: record {
    context_list: Context_list &optional;
    default_contact_list: Default_Context_List &optional;
  };

  type ASOI_tag: vector of record {
    qualifier: ASO_qualifier &optional;
    identifier: ASOI_identifier &optional;
  };

  type Association_data: vector of EXTERNALt;

  type AARQ_apdu: record {
    protocol_version: vector of enum {
      AARQ_apdu_version1,
  };
    aSO_context_name: ASO_context_name;
    called_AP_title: AP_title &optional;
    called_AE_qualifier: AE_qualifier &optional;
    called_AP_invocation_identifier: AP_invocation_identifier &optional;
    called_AE_invocation_identifier: AE_invocation_identifier &optional;
    calling_AP_title: AP_title &optional;
    calling_AE_qualifier: AE_qualifier &optional;
    calling_AP_invocation_identifier: AP_invocation_identifier &optional;
    calling_AE_invocation_identifier: AE_invocation_identifier &optional;
    sender_acse_requirements: ACSE_requirements &optional;
    mechanism_name: Mechanism_name &optional;
    calling_authentication_value: Authentication_value &optional;
    aSO_context_name_list: ASO_context_name_list &optional;
    implementation_information: Implementation_data &optional;
    p_context_definition_list: Syntactic_context_list &optional;
    called_asoi_tag: ASOI_tag &optional;
    calling_asoi_tag: ASOI_tag &optional;
    user_information: Association_data &optional;
  };

  type Associate_source_diagnostic: record {
    service_user: enum {
      null = 0,
      Associate_source_diagnostic_no_reason_given = 1,
      application_context_name_not_supported = 2,
      calling_AP_title_not_recognized = 3,
      calling_AP_invocation_identifier_not_recognized = 4,
      calling_AE_qualifier_not_recognized = 5,
      calling_AE_invocation_identifier_not_recognized = 6,
      called_AP_title_not_recognized = 7,
      called_AP_invocation_identifier_not_recognized = 8,
      called_AE_qualifier_not_recognized = 9,
      called_AE_invocation_identifier_not_recognized = 10,
      Associate_source_diagnostic_authentication_mechanism_name_not_recognized = 11,
      Associate_source_diagnostic_authentication_mechanism_name_required = 12,
      Associate_source_diagnostic_authentication_failure = 13,
      Associate_source_diagnostic_authentication_required = 14,
    } &optional;
    service_provider: enum {
      null = 0,
      Associate_source_diagnostic_no_reason_given = 1,
      no_common_acse_version = 2,
    } &optional;
  };

  type Concrete_syntax_name: TransferSyntaxName;

  type P_context_result_list: vector of record {
    result: Result;
    concrete_syntax_name: Concrete_syntax_name &optional;
    provider_reason: enum {
      reason_not_specified = 0,
      abstract_syntax_not_supported = 1,
      proposed_transfer_syntaxes_not_supported = 2,
      local_limit_on_DCS_exceeded = 3,
    } &optional;
  };

  type AARE_apdu: record {
    protocol_version: vector of enum {
      AARE_apdu_version1,
  };
    aSO_context_name: ASO_context_name;
    result: Associate_result;
    result_source_diagnostic: Associate_source_diagnostic;
    responding_AP_title: AP_title &optional;
    responding_AE_qualifier: AE_qualifier &optional;
    responding_AP_invocation_identifier: AP_invocation_identifier &optional;
    responding_AE_invocation_identifier: AE_invocation_identifier &optional;
    responder_acse_requirements: ACSE_requirements &optional;
    mechanism_name: Mechanism_name &optional;
    responding_authentication_value: Authentication_value &optional;
    aSO_context_name_list: ASO_context_name_list &optional;
    implementation_information: Implementation_data &optional;
    p_context_result_list: P_context_result_list &optional;
    called_asoi_tag: ASOI_tag &optional;
    calling_asoi_tag: ASOI_tag &optional;
    user_information: Association_data &optional;
  };

  type RLRQ_apdu: record {
    reason: Release_request_reason &optional;
    aso_qualifier: ASO_qualifier &optional;
    asoi_identifier: ASOI_identifier &optional;
    user_information: Association_data &optional;
  };

  type RLRE_apdu: record {
    reason: Release_response_reason &optional;
    aso_qualifier: ASO_qualifier &optional;
    asoi_identifier: ASOI_identifier &optional;
    user_information: Association_data &optional;
  };

  type ABRT_apdu: record {
    abort_source: ABRT_source;
    abort_diagnostic: ABRT_diagnostic &optional;
    aso_qualifier: ASO_qualifier &optional;
    asoi_identifier: ASOI_identifier &optional;
    user_information: Association_data &optional;
  };

  type User_information: Association_data;

  type PDV_list: record {
    transfer_syntax_name: TransferSyntaxName &optional;
    presentation_context_identifier: Presentation_context_identifier &optional;
    presentation_data_values: record {
      simple_ASN1_type: string &optional;
      octet_aligned: string &optional;
      arbitrary: string &optional;
    } &optional;
  };

  type User_Data: record {
    user_information: User_information &optional;
    simply_encoded_data: Simply_encoded_data &optional;
    fully_encoded_data: PDV_list &optional;
  };

  type A_DT_apdu: record {
    aso_qualifier: ASO_qualifier &optional;
    asoi_identifier: ASOI_identifier &optional;
    a_user_data: User_Data &optional;
  };

  type ACRQ_apdu: record {
    aso_qualifier: ASO_qualifier &optional;
    asoi_identifier: ASOI_identifier &optional;
    aSO_context_name: ASO_context_name &optional;
    aSO_context_name_list: ASO_context_name_list &optional;
    p_context_definition_list: Syntactic_context_list &optional;
    user_information: User_information &optional;
  };

  type ACRP_apdu: record {
    aso_qualifier: ASO_qualifier &optional;
    asoi_identifier: ASOI_identifier &optional;
    aSO_context_name: ASO_context_name &optional;
    p_context_result_list: P_context_result_list &optional;
    user_information: User_information &optional;
  };

  type ACSE_apdu: record {
    aarq: AARQ_apdu &optional;
    aare: AARE_apdu &optional;
    rlrq: RLRQ_apdu &optional;
    rlre: RLRE_apdu &optional;
    abrt: ABRT_apdu &optional;
    adt: A_DT_apdu &optional;
    acrq: ACRQ_apdu &optional;
    acrp: ACRP_apdu &optional;
  };

  type Application_context_name: ASO_context_name;

  type AE_title_form1: Name;

  type AE_title: record {
    ae_title_form1: AE_title_form1 &optional;
    ae_title_form2: AE_title_form2 &optional;
  };

}
