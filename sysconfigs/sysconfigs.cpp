#include <QRegularExpression>
#include <QSettings>
#include <QSet>
#include <QTextCodec>

#include "literal_strings/literal_strings.h"
#include "logger/logger.h"
#include "common_tools/common_tool_func.h"
#include "sysconfigs/sysconfigs.h"
#include "common_tools/common_tool_func.h"

#undef ENUM_NAME_DEF
#define ENUM_NAME_DEF(e, ...) <<(e)

static const char* gs_sysconfigs_file_fpn = "./configs/configs.ini";

static const char* gs_ini_grp_sys_cfgs = "sys_cfgs";
static const char* gs_ini_key_log_level = "log_level";

static const char* gs_ini_grp_rmt_ip_port = "rmt_ip_port";
static const char* gs_ini_key_rmt_ip = "rmt_ip";
static const char* gs_ini_key_rmt_port = "rmt_port";
static const char* gs_ini_key_prot = "prot";

static const char* gs_ini_grp_test_params = "test_params";
static const char* gs_ini_key_send_fail_retry_wait_s = "send_fail_retry_wait_s";
static const char* gs_ini_key_cmd1_name = "cmd1_name";
static const char* gs_ini_key_cmd1_content = "cmd1_content";
static const char* gs_ini_key_cmd1_dura_s = "cmd1_dura_s";
static const char* gs_ini_key_cmd2_name = "cmd2_name";
static const char* gs_ini_key_cmd2_content = "cmd2_content";
static const char* gs_ini_key_cmd2_dura_s = "cmd2_dura_s";

static const char* gs_ini_grp_ping_params = "ping_params";
static const char* gs_ini_key_check_ping = "check_ping";
static const char* gs_ini_key_ping_int_between_s_r = "ping_int_between_s_r";
static const char* gs_ini_key_ping_wait_dura_s = "ping_wait_dura_s";
static const char* gs_ini_key_ping_int_between_r_s = "ping_int_between_r_s";
static const char* gs_ini_key_ping_miss_count = "ping_miss_count";
static const char* gs_ini_key_ping_data = "ping_data";

static const bool gs_def_check_ping = true;
const int g_def_ping_int_between_s_r = 2;
const int g_def_ping_wait_dura_s = 2;
const int g_def_ping_int_between_r_s = 3;
const int g_def_ping_miss_count = 3;
const char * g_def_ping_data = "reachable_test";

sys_configs_struct_t g_sys_configs_block;

static const LOG_LEVEL gs_def_log_level = LOG_ERROR;

static const char* gs_def_rmt_ip = "192.168.2.7";
static const quint16 gs_def_rmt_port = 8020;
static const char* gs_def_prot = "tcp";
const char* g_prot_udp_str = "udp";
const char* g_prot_tcp_str = "tcp";
const char* g_prot_tcp_server_str = "tcp_server";

static const double gs_def_send_fail_retry_wait_s = 5;
static QString gs_def_cmd1_name = "启动曝光";
static const char* gs_def_cmd1_content = "AA 55";
static const double gs_def_cmd1_dura_s = 10;

static QString gs_def_cmd2_name = "停止曝光";
static const char* gs_def_cmd2_content = "BB 55";
static const double gs_def_cmd2_dura_s = 30;

static RangeChecker<int> gs_cfg_file_log_level_ranger((int)LOG_DEBUG, (int)LOG_ERROR, "",
                     EDGE_INCLUDED, EDGE_INCLUDED);

static RangeChecker<int> gs_cfg_file_value_ge0_int_ranger(0, 0, "",
                           EDGE_INCLUDED, EDGE_INFINITE);

static RangeChecker<double> gs_cfg_file_value_ge0_double_ranger(0, 0, "",
                       EDGE_INCLUDED, EDGE_INFINITE);

static RangeChecker<int> gs_cfg_file_value_gt0_int_ranger(0, 0, "",
                       EDGE_EXCLUDED, EDGE_INFINITE);

static RangeChecker<int> gs_cfg_file_value_01_int_ranger(0, 1, "",
                       EDGE_INCLUDED, EDGE_INCLUDED);

static RangeChecker<double> gs_cfg_file_value_gt0_double_ranger(0, 0, "",
                       EDGE_EXCLUDED, EDGE_INFINITE);

#define REC_CFG_RET_ERR(key, var) \
        cfg_ret = false;\
        ret_str += (ret_str.isEmpty() ? "" : "\n"); \
        ret_str += QString("%1 %2 %3: %4").arg(g_str_param_in_cfg_file, (key), g_str_error)\
                                            .arg(var);

/*the __VA_ARGS__ should be empty or a type converter like (cust_type).*/
#define GET_INF_CFG_NUMBER_VAL(settings, key, val_func, var, def, factor, checker, ...) \
{\
    cfg_ret = true; \
    if((settings).contains(key)) \
    {\
        (var) = __VA_ARGS__((factor) * ((settings).value(key).val_func()));\
    }\
    else \
    {\
        (var) = __VA_ARGS__((factor) * (def));\
    }\
    if((checker) && !((checker)->range_check(var)))\
    {\
        REC_CFG_RET_ERR(key, var) \
        ret_str += QString("\n%1 %2").arg(g_str_should_be_in_range, (checker)->range_str()); \
    }\
    ret = ret && cfg_ret;\
}

#define GET_INF_CFG_NUMBER_VAL_2(settings, key, val_func, var, tmp, def, factor, checker, ...) \
{\
    cfg_ret = true; \
    if((settings).contains(key)) \
    {\
        (tmp) = ((factor) * ((settings).value(key).val_func()));\
    }\
    else \
    {\
        (tmp) = ((factor) * (def));\
    }\
    if((checker) && !((checker)->range_check(tmp)))\
    {\
        REC_CFG_RET_ERR(key, tmp) \
        ret_str += QString("\n%1 %2").arg(g_str_should_be_in_range, (checker)->range_str()); \
    }\
    else \
    {\
        (var) = __VA_ARGS__(tmp); \
    }\
    ret = ret && cfg_ret;\
}

//var SHOULD be for type QString
#define GET_INF_CFG_STRING_VAL(settings, key, var, def, validate) \
{\
    cfg_ret = true; \
    if((settings).contains(key)) \
    {\
        (var) = (settings).value(key).toString();\
    }\
    else \
    {\
        (var) = (def);\
    }\
    if(!(validate))\
    {\
        REC_CFG_RET_ERR(key, var)\
    }\
    ret = ret && cfg_ret;\
}

#define GET_INF_CFG_BYTEARRAY_VAL(settings, key, var, def, hex, sep) \
{\
    QString tmp_str; \
    GET_INF_CFG_STRING_VAL(settings, key, tmp_str, def, !tmp_str.isEmpty()); \
    if(cfg_ret) \
    {\
        if(hex) \
        {\
            tmp_str.remove(sep);\
            if(tmp_str.isEmpty()) \
            {\
                cfg_ret = false; \
            }\
            else \
            {\
                (var) = QByteArray::fromHex(tmp_str.toUtf8()); \
                if((var).isEmpty()) cfg_ret = false;\
            }\
            if(!cfg_ret)\
            {\
                REC_CFG_RET_ERR(key, tmp_str) \
            }\
        }\
        else \
        {\
            (var) = tmp_str.toUtf8();\
        }\
    }\
    ret = ret && cfg_ret;\
}

#define CHECK_ENUM(e_type, init_e_set, e_v, str_func, title_str) \
{\
    cfg_ret = true; \
    QSet<e_type> e_set; \
    init_e_set; \
    if(!e_set.contains(e_v))\
    {\
        cfg_ret = false;\
        ret_str += (ret_str.isEmpty() ? "" : "\n"); \
        ret_str += QString(title_str) + g_str_should_be_one_val_of + "\n{";\
        auto it = e_set.constBegin();\
        while(it != e_set.constEnd()) {ret_str += str_func(*it) + ", "; ++it;}\
        ret_str.chop(2);\
        ret_str += "}\n";\
        ret_str += QString("%1: %2\n").arg(gs_str_actual_val, str_func(e_v)); \
    }\
    ret = ret && cfg_ret;\
}

/*check the validation of config parameters.*/
#define CHECK_LIMIT_RANGE(l_name, min_l, max_l, checker, unit_str) \
{\
    cfg_ret = true; \
    if(((checker) && (!((checker)->range_check(min_l)) || !((checker)->range_check(max_l)))) \
        || ((min_l) > (max_l)))\
    {\
        cfg_ret = false;\
        ret_str += (ret_str.isEmpty() ? "" : "\n"); \
        ret_str += QString((l_name)) + \
                   " [" + QString::number((min_l)) + ", " + QString::number((max_l)) + "] " +\
                   (unit_str) + "\n";\
    }\
    ret = ret && cfg_ret;\
}

bool fill_sys_configs(QString * ret_str_ptr)
{
    bool ret = true, cfg_ret = true;
    QString ret_str;
    QSettings settings(gs_sysconfigs_file_fpn, QSettings::IniFormat);

    settings.setIniCodec(QTextCodec::codecForName("UTF-8"));
    /*--------------------*/
    settings.beginGroup(gs_ini_grp_sys_cfgs);
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_log_level, toInt,
                           g_sys_configs_block.log_level, gs_def_log_level,
                           1, &gs_cfg_file_log_level_ranger, (LOG_LEVEL));
    settings.endGroup();

    /*--------------------*/
    settings.beginGroup(gs_ini_grp_rmt_ip_port);
    GET_INF_CFG_STRING_VAL(settings, gs_ini_key_rmt_ip, g_sys_configs_block.rmt_ip_port.ip,
                           gs_def_rmt_ip, ip_addr_valid(g_sys_configs_block.rmt_ip_port.ip));
    int tmp_port_val;
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_rmt_port, toInt,
                           g_sys_configs_block.rmt_ip_port.port, gs_def_rmt_port,
                           1, &g_ip_port_ranger, (quint16));
    GET_INF_CFG_NUMBER_VAL_2(settings, gs_ini_key_rmt_port, toInt,
                           g_sys_configs_block.rmt_ip_port.port, tmp_port_val, gs_def_rmt_port,
                           1, &g_ip_port_ranger, (quint16));

    GET_INF_CFG_STRING_VAL(settings, gs_ini_key_prot, g_sys_configs_block.rmt_ip_port.prot,
                           gs_def_prot, (g_sys_configs_block.rmt_ip_port.prot == g_prot_udp_str
                                     || g_sys_configs_block.rmt_ip_port.prot == g_prot_tcp_str
                                     || g_sys_configs_block.rmt_ip_port.prot == g_prot_tcp_server_str ));
    settings.endGroup();

    /*--------------------*/

    settings.beginGroup(gs_ini_grp_test_params);

    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_send_fail_retry_wait_s, toDouble,
                           g_sys_configs_block.cmd_blk.send_fail_retry_wait_s,
                           gs_def_send_fail_retry_wait_s,
                           1, &gs_cfg_file_value_gt0_double_ranger);

    static QRegularExpression cmd_content_sps("[ \t]+");
    GET_INF_CFG_STRING_VAL(settings, gs_ini_key_cmd1_name,
                           g_sys_configs_block.cmd_blk.cmd1_name, gs_def_cmd1_name, true);
    GET_INF_CFG_BYTEARRAY_VAL(settings, gs_ini_key_cmd1_content,
                              g_sys_configs_block.cmd_blk.cmd1_content, gs_def_cmd1_content,
                              true, cmd_content_sps);
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_cmd1_dura_s, toDouble,
                           g_sys_configs_block.cmd_blk.cmd1_dura_s, gs_def_cmd1_dura_s,
                           1, &gs_cfg_file_value_gt0_double_ranger);

    GET_INF_CFG_STRING_VAL(settings, gs_ini_key_cmd2_name,
                           g_sys_configs_block.cmd_blk.cmd2_name, gs_def_cmd2_name, true);
    GET_INF_CFG_BYTEARRAY_VAL(settings, gs_ini_key_cmd2_content,
                              g_sys_configs_block.cmd_blk.cmd2_content, gs_def_cmd2_content,
                              true, cmd_content_sps);
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_cmd2_dura_s, toDouble,
                           g_sys_configs_block.cmd_blk.cmd2_dura_s, gs_def_cmd2_dura_s,
                           1, &gs_cfg_file_value_gt0_double_ranger);

    settings.endGroup();

    /*--------------------*/

    /*--------------------*/
    settings.beginGroup(gs_ini_grp_ping_params);
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_check_ping, toInt,
                           g_sys_configs_block.ping_params.check_ping,
                           gs_def_check_ping,
                           1, (RangeChecker<int>*)0, (bool));
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_ping_int_between_s_r, toInt,
                           g_sys_configs_block.ping_params.ping_int_between_s_r,
                           g_def_ping_int_between_s_r,
                           1, &gs_cfg_file_value_gt0_int_ranger);
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_ping_wait_dura_s, toInt,
                           g_sys_configs_block.ping_params.ping_wait_dura_s,
                           g_def_ping_wait_dura_s,
                           1, &gs_cfg_file_value_gt0_int_ranger);
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_ping_int_between_r_s, toInt,
                           g_sys_configs_block.ping_params.ping_int_between_r_s,
                           g_def_ping_int_between_r_s,
                           1, &gs_cfg_file_value_gt0_int_ranger);
    GET_INF_CFG_NUMBER_VAL(settings, gs_ini_key_ping_miss_count, toInt,
                           g_sys_configs_block.ping_params.ping_miss_count,
                           g_def_ping_miss_count,
                           1, &gs_cfg_file_value_gt0_int_ranger);
    GET_INF_CFG_BYTEARRAY_VAL(settings, gs_ini_key_ping_data,
                           g_sys_configs_block.ping_params.ping_data, g_def_ping_data,
                           false, "");

    settings.endGroup();
    /*--------------------*/

    if(ret_str_ptr) *ret_str_ptr = ret_str;
    return ret;
}
