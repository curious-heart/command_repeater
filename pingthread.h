
#ifndef PINGTHREAD_H
#define PINGTHREAD_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QTimer>

#if defined(Q_OS_WIN)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib") // 链接 Winsock 库
#else
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#endif

#include "sysconfigs/sysconfigs.h"

/*
 * the "static_assert(true);" is added according the the following link to eliminate warning.
 *  https://stackoverflow.com/questions/72456118/why-does-clang-give-a-warning-unterminated-pragma-pack-push-at-end-of-f
*/
static_assert(true);
// 定义 ICMP 请求头部结构体// 确保结构体按 1 字节对齐
#pragma pack(push, 1)
typedef struct
{
    uint8_t type;          // ICMP 类型，8:请求, 0:回复
    uint8_t code;          // ICMP 代码，通常为 0
    uint16_t checksum;     // 校验和
    uint16_t id;           // 请求标识符
    uint16_t sequence;     // 序列号
}IcmpHeader ;

#if defined(Q_OS_WIN)
typedef struct
{
    uint8_t  ip_hl:4,      // IP 头部长度
             ip_v:4;       // IP 版本
    uint8_t  ip_tos;       // 服务类型
    uint16_t ip_len;       // 总长度
    uint16_t ip_id;        // 标识符
    uint16_t ip_off;       // 分段偏移
    uint8_t  ip_ttl;       // 生存时间
    uint8_t  ip_p;         // 协议
    uint16_t ip_sum;       // 校验和
    uint32_t ip_src;       // 源 IP 地址
    uint32_t ip_dst;       // 目的 IP 地址
}IpHeader;
#endif
// 恢复默认对齐
#pragma pack(pop)

#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_CODE 0

class PingThread : public QObject {
    Q_OBJECT

public:
    explicit PingThread(QObject *parent = nullptr);
    ~PingThread();

    bool m_init_ok;

public slots:
    void start_ping_hdlr(const QString ip, int int_between_s_r = g_def_ping_int_between_s_r,
                        int waitTimeSec = g_def_ping_wait_dura_s,
                        int int_between_r_s = g_def_ping_int_between_r_s,
                        int maxMissCount = g_def_ping_miss_count,
                const QByteArray data = QByteArray(g_def_ping_data, qstrlen(g_def_ping_data)));
    void stop_ping_hdlr();

private slots:
    void time_to_recv();
    void ping();

signals:
    void target_unavaliable_sig();

private:
    bool sendIcmpRequest(const QString &ipAddress);
    bool receiveIcmpResponse(unsigned short id, unsigned short sequence, int timeout);
    void check_miss();
    unsigned short checksum(void *b, int len);

private:
    QString m_targetIp;
    int m_int_between_s_r;
    int m_waitTimeSec;
    int m_int_between_r_s;
    int m_maxMissCount;
    QByteArray m_pingData;

    int m_continuousMissedCount;
    int m_targetUnavailableCount;
    bool m_stopRequested;
#if defined(Q_OS_WIN)
    SOCKET m_sock;
#else
    int m_sock;
#endif

#if defined(Q_OS_WIN)
    WSADATA m_wsaData;
#else
    struct sockaddr_in m_sourceAddr;
#endif

    quint16 m_proc_id, m_icmp_sequence;
    QTimer *m_pingTimer, *m_recvTimer;
};

#endif // PINGTHREAD_H
