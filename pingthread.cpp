#include "pingthread.h"
#include <QDebug>
#include "logger/logger.h"
#if defined(Q_OS_WIN)
#else
#include <errno.h>
#endif


static QString get_err_string()
{
    QString err_str;
#if defined(Q_OS_WIN)
    err_str = QString("%1").arg(WSAGetLastError());
#else
    err_str = QString("%1:%2").arg(errno).arg(strerror(errno));
#endif
      return err_str;
}

PingThread::PingThread(QObject *parent)
    : QObject(parent),
      m_init_ok(false),
      m_continuousMissedCount(0),
      m_targetUnavailableCount(0),
      m_stopRequested(false),
#if defined(Q_OS_WIN)
      m_sock(INVALID_SOCKET)
#else
      m_sock(-1)
#endif
{
#if defined(Q_OS_WIN)
    // Windows平台初始化
    if (WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0)
    {
        DIY_LOG(LOG_ERROR, "WSAStartup failed!");
        return;
    }
    m_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (m_sock == INVALID_SOCKET)
    {
        DIY_LOG(LOG_ERROR, "Socket creation failed!");
        return;
    }
#else
    // Linux平台初始化
    // Nothing needed here for Linux as it's ready for raw sockets

    m_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (m_sock < 0)
    {
        DIY_LOG(LOG_ERROR, QString("Socket creation failed: %1 %2").arg(errno).arg(strerror(errno)));
        return;
    }
#endif
    m_pingTimer = new QTimer(this);
    m_pingTimer->setSingleShot(true);
    connect(m_pingTimer, &QTimer::timeout, this, &PingThread::ping, Qt::QueuedConnection);

    m_recvTimer = new QTimer(this);
    m_recvTimer->setSingleShot(true);
    connect(m_recvTimer, &QTimer::timeout, this, &PingThread::time_to_recv, Qt::QueuedConnection);

    m_icmp_sequence = 1;
#if defined(Q_OS_WIN)
    m_proc_id = static_cast<unsigned short>(GetCurrentProcessId());
#else
    m_proc_id = static_cast<unsigned short>(getpid());
#endif

    m_init_ok = true;
}

PingThread::~PingThread() {
    stop_ping_hdlr();

#if defined(Q_OS_WIN)
    // Windows平台清理
    if (m_sock != INVALID_SOCKET) {
        closesocket(m_sock);
    }
    WSACleanup();
#else
    // Linux平台清理
    if (m_sock >= 0) {
        close(m_sock);
    }
#endif
}

void PingThread::start_ping_hdlr(const QString ip, int int_between_s_r, int waitTimeSec,
                        int int_between_r_s, int maxMissCount, const QByteArray data)
{
    m_targetIp = ip;
    m_int_between_s_r = int_between_s_r;
    m_waitTimeSec = waitTimeSec;
    m_int_between_r_s = int_between_r_s;
    m_maxMissCount = maxMissCount;
    m_pingData = data;
    m_continuousMissedCount = 0;
    m_targetUnavailableCount = 0;
    m_stopRequested = false;

    m_pingTimer->start(0);
}

void PingThread::stop_ping_hdlr() {
    m_stopRequested = true;
    if(m_pingTimer) m_pingTimer->stop();  // 停止定时器
    if(m_recvTimer) m_recvTimer->stop();
}

void PingThread::ping()
{
    if (m_stopRequested) return;

    ++m_icmp_sequence;
    if(!sendIcmpRequest(m_targetIp))
    {
        m_continuousMissedCount++;
        check_miss();
        m_pingTimer->start(m_int_between_r_s * 1000);
    }
    else
    {
        m_recvTimer->start(m_int_between_s_r * 1000);
    }
}

void PingThread::time_to_recv()
{
    if(!receiveIcmpResponse(m_proc_id, m_icmp_sequence, m_waitTimeSec))
    {
        m_continuousMissedCount++;
        check_miss();
    } else {
        m_continuousMissedCount = 0;  // 重置计数
    }

    m_pingTimer->start(m_int_between_r_s * 1000);
}

bool PingThread::sendIcmpRequest(const QString &ipAddress)
{
    struct sockaddr_in dest_addr;
    QByteArray icmp_pkt;
    IcmpHeader *icmp_header;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = 0;
    if (inet_pton(AF_INET, ipAddress.toStdString().c_str(), &dest_addr.sin_addr) <= 0)
    {
        DIY_LOG(LOG_ERROR, "Invalid IP address format");
        return false;
    }

    icmp_pkt.resize(sizeof(IcmpHeader) + m_pingData.size());
    icmp_pkt.fill(0);
    icmp_header = (IcmpHeader*)icmp_pkt.data();

    icmp_header->type = ICMP_ECHO_REQUEST_TYPE;  // Echo Request (ICMP_ECHO)
    icmp_header->code = ICMP_ECHO_CODE;
    icmp_header->id = htons(m_proc_id);
    icmp_header->sequence = htons(m_icmp_sequence);
    char* ping_data_ptr = icmp_pkt.data() + sizeof(IcmpHeader);
    memcpy(ping_data_ptr, m_pingData.data(), m_pingData.size());
    icmp_header->checksum = 0;
    icmp_header->checksum = checksum(icmp_pkt.data(), icmp_pkt.size());

#if defined(Q_OS_WIN)
    int bytesSent = sendto(m_sock, icmp_pkt.data(), icmp_pkt.size(), 0,
                           (SOCKADDR *)&dest_addr, sizeof(dest_addr));
    if (bytesSent == SOCKET_ERROR)
    {
        DIY_LOG(LOG_ERROR, QString("send error: %1").arg(get_err_string()));
        return false;
    }
#else
    int bytesSent = sendto(m_sock, icmp_pkt.data(), icmp_pkt.size(), 0,
                           (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (bytesSent < 0)
    {
        DIY_LOG(LOG_ERROR, QString("send error: %1").arg(get_err_string()));
        return false;
    }
#endif

    DIY_LOG(LOG_INFO, QString("ping sent to %1, data: %2").arg(ipAddress,
                            m_pingData.toHex(' ').rightJustified(2, '0').toUpper()));

    return true;
}

bool PingThread::receiveIcmpResponse(unsigned short id, unsigned short sequence, int timeout) {
    char buffer[1024];
    struct sockaddr_in fromAddr;
    socklen_t addrLen = sizeof(fromAddr);

    int recv_len;

    // 设置 recvfrom 的超时
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    int sock_op = setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    if(sock_op != 0)
    {
        DIY_LOG(LOG_ERROR, QString("setsockopt error: %1.").arg(get_err_string()));
        return false;
    }

    recv_len = recvfrom(m_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&fromAddr, &addrLen);
    if (recv_len < 0)
    {
        QString err_str = get_err_string();
        DIY_LOG(LOG_ERROR, QString("recv error: %1").arg(err_str));
        return false;
    }

#if defined(Q_OS_WIN)
    IpHeader *ip_header = (IpHeader *)buffer;
#else
    struct ip *ip_header = (struct ip *)buffer;
#endif
    IcmpHeader *icmp_header = (IcmpHeader *)(buffer + (ip_header->ip_hl << 2));

    // 检查是否为 ICMP Echo 回复，类型为 0 (Echo Reply)，并且 ID 和序列号匹配
    if (icmp_header->type == ICMP_ECHO_REPLY_TYPE && ntohs(icmp_header->id) == id
            && ntohs(icmp_header->sequence) == sequence)
    {
        DIY_LOG(LOG_INFO, QString("ping response received."));
        return true;  // 收到有效的 ICMP Echo 回复
    }
    else
    {
        QString err_str = "Error icmp echo received:\n";
        err_str += QString("type(r):%1;\nid(r): %2, id should be: %3;\nseq(r): %4, seq should be: %5")
                .arg(icmp_header->type).arg(ntohs(icmp_header->id)).arg(id)
                .arg(ntohs(icmp_header->sequence)).arg(sequence);
        DIY_LOG(LOG_ERROR, err_str);
        return false;
    }
}

void PingThread::check_miss()
{
    if (m_continuousMissedCount >= m_maxMissCount)
    {
        emit target_unavaliable_sig();
        m_continuousMissedCount = 0;  // 重置计数
        ++m_targetUnavailableCount;
    }
}

unsigned short PingThread::checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}
