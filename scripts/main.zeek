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
        auth_failure:        bool       &log &default=F;
        result:              string     &log &optional;
        aborted:             bool       &log &default=F;
        diag:                string     &log &optional;
    };

    global log_acse: event(rec: Info);

    redef enum Notice::Type += {
		Password_Guessing,
	};

	const password_guesses_limit: double = 30 &redef;
	const guessing_timeout = 30 mins &redef;
	const ignore_guessers: table[subnet] of subnet &redef;
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

function enable_bruteforce_detection() {
    local r1: SumStats::Reducer = [$stream="acse.login.failure", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=5];
	SumStats::create([$name="detect-acse-bruteforcing",
	                  $epoch=guessing_timeout,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["acse.login.failure"]$sum;
	                  	},
	                  $threshold=password_guesses_limit,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["acse.login.failure"];
	                  	local sub_msg = fmt("Sampled servers: ");
	                  	local samples = r$samples;
	                  	for ( i in samples )
	                  		{
	                  		if ( samples[i]?$str )
	                  			sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
	                  		}
	                  	# Generate the notice.
	                  	NOTICE([$note=Password_Guessing,
	                  	        $msg=fmt("%s appears to be guessing ACSE passwords (seen in %d connections).", key$host, r$num),
	                  	        $sub=sub_msg,
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
}

function auth_failure(c: connection) {
    if (!(c$id$orig_h in ignore_guessers &&
          c$id$resp_h in ignore_guessers[c$id$orig_h]) ) {
        SumStats::observe("acse.login.failure", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
    }
}

event zeek_init() &priority=5 {
    Log::create_stream(acse::LOG, [$columns = Info, $ev = log_acse, $path="acse"]);
    enable_bruteforce_detection();
}

event aarq_apdu(c: connection, is_orig: bool, apdu: AARQ_apdu) {
    local info = get_info(c);

    if(!info?$context_name) info$context_name = apdu$aSO_context_name;

    if(!info?$auth_mechanism)
        if(apdu?$mechanism_name)
            info$auth_mechanism = apdu$mechanism_name;

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

    if(!info?$called_ap_title)
        if(aare?$responding_AP_title)
            info$called_ap_title = ap_title_to_str(aare$responding_AP_title);

    if(aare?$result_source_diagnostic && aare$result_source_diagnostic$service_user != acse::null) {
        info$diag = cat(aare $ result_source_diagnostic $ service_user);
        if(aare$result_source_diagnostic$service_user == Associate_source_diagnostic_authentication_failure) {
            info$auth_failure = T;
            auth_failure(c);
        }
    }
}

event abrt_apdu(c: connection, is_orig: bool, abrt: ABRT_apdu) {
    local info = get_info(c);

    info$aborted = T;
    if(abrt?$abort_diagnostic) {
        info$diag = cat(abrt$abort_diagnostic);
        if(abrt$abort_diagnostic==ABRT_diagnostic_authentication_failure) {
            info$auth_failure = T;
            auth_failure(c);
        }
    }
}

event connection_state_remove(c: connection) {
    if ( c?$acse_info ) {
        Log::write(LOG, c$acse_info);
        delete c$acse_info;
    }
}
