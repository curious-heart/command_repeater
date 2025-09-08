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
    LOG_LEVEL log_level;
    site_ip_port_s_t rmt_ip_port;
    cmd_blk_s_t cmd_blk;
}sys_configs_struct_t;

extern sys_configs_struct_t g_sys_configs_block;

bool fill_sys_configs(QString *);

#endif // SYSCONFIGS_H
