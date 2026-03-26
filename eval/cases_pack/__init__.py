from eval.cases_pack.a_sql_cmd import cases_sql_cmd
from eval.cases_pack.b_xss import cases_xss
from eval.cases_pack.c_path_proto_redirect import cases_path_proto_redirect
from eval.cases_pack.d_sec_des_crypto import cases_sec_des_crypto
from eval.cases_pack.e_nosql_ssrf_redos import cases_nosql_ssrf_redos
from eval.cases_pack.f_special import cases_special


def all_cases() -> list[dict]:
    return [
        *cases_sql_cmd(),
        *cases_xss(),
        *cases_path_proto_redirect(),
        *cases_sec_des_crypto(),
        *cases_nosql_ssrf_redos(),
        *cases_special(),
    ]
