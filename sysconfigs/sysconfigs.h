#ifndef SYSCONFIGS_H
#define SYSCONFIGS_H

#include <QString>

#include "logger/logger.h"

typedef struct
{
    QString ip;
    quint16 port;
}site_ip_port_s_t;

typedef struct
{
    QString cmd1_name;
    QByteArray cmd1_content;
    double cmd1_dura_s;
    QString cmd2_name;
    QByteArray cmd2_content;
    double cmd2_dura_s;
}cmd_blk_s_t;

typedef struct
{
    bool check_ping;
    int ping_int_between_s_r, ping_wait_dura_s;
    int ping_int_between_r_s;
    int ping_miss_count;
    QByteArray ping_data;
}ping_params_s_t;

typedef struct
{
    LOG_LEVEL log_level;
    site_ip_port_s_t rmt_ip_port;
    cmd_blk_s_t cmd_blk;
    ping_params_s_t ping_params;
}sys_configs_struct_t;

extern const int g_def_ping_int_between_s_r;
extern const int g_def_ping_wait_dura_s;
extern const int g_def_ping_int_between_r_s;
extern const int g_def_ping_miss_count;
extern const char * g_def_ping_data;

extern sys_configs_struct_t g_sys_configs_block;

bool fill_sys_configs(QString *);

#endif // SYSCONFIGS_H
