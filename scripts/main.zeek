module acse;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                  time       &log;
        uid:                 string     &log;
        id:                  conn_id    &log;
        context_name:        string     &log &optional;
        calling_ap_title:    string     &log &optional;
        called_ap_title:     string     &log &optional;
        auth_mechanism:      string     &log &optional;
        result:              string     &log &optional;
        aborted:             bool       &log &default=F;
        diag:                string     &log &optional;
    };

    global log_acse: event(rec: Info);

}

redef record connection += {
    acse_info: Info &optional;
};

function get_info(c: connection): Info {
    if(!c?$acse_info) {
        c$acse_info = [
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
        ];
    }
    return c$acse_info;
}

function ap_title_to_str(title: AP_title): string {
    if(title ?$ ap_title_form1) {
        return cat(title $ ap_title_form1);
    } else if(title ?$ ap_title_form2) {
        return title $ ap_title_form2;
    } else if(title ?$ ap_title_form3) {
        return title $ ap_title_form3;
    } else {
        return "<UNKNOWN>";
    }
}

event zeek_init() &priority=5 {
    Log::create_stream(acse::LOG, [$columns = Info, $ev = log_acse, $path="acse"]);
}

event aarq_apdu(c: connection, is_orig: bool, apdu: AARQ_apdu) {
    local info = get_info(c);

    if(!info?$context_name) info$context_name = apdu$aSO_context_name;

    if(!info?$calling_ap_title)
        if(apdu?$calling_AP_title)
            info$calling_ap_title = ap_title_to_str(apdu$calling_AP_title);

    if(!info?$called_ap_title)
        if(apdu?$called_AP_title)
            info$called_ap_title = ap_title_to_str(apdu$called_AP_title);
}

event aare_apdu(c: connection, is_orig: bool, aare: AARE_apdu) {
    local info = get_info(c);

    if(!info?$context_name) info$context_name = aare$aSO_context_name;
    if(!info?$result) info$result = split_string1(cat(aare$result), /::/)[-1];

    # if the responding ap is different from the called ap the answering ap is logged
    if(!info?$called_ap_title)
        if(aare?$responding_AP_title)
            info$called_ap_title = ap_title_to_str(aare$responding_AP_title);

    if(aare?$mechanism_name)
        info$auth_mechanism = aare$mechanism_name;

    if(aare?$result_source_diagnostic && aare$result_source_diagnostic$service_user != acse::null)
        info$diag = cat(aare $ result_source_diagnostic $ service_user);
}

event abrt_apdu(c: connection, is_orig: bool, abrt: ABRT_apdu) {
    local info = get_info(c);

    info$aborted = T;
    if(abrt?$abort_diagnostic)
        info$diag = cat(abrt$abort_diagnostic);
}

event connection_state_remove(c: connection) {
    if ( c?$acse_info ) {
        Log::write(LOG, c$acse_info);
        delete c$acse_info;
    }
}
