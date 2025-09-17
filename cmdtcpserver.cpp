#include "logger/logger.h"
#include "cmdtcpserver.h"

CmdTcpServer::CmdTcpServer(QObject *parent)
    : QTcpServer(parent)
{
}

CmdTcpServer::~CmdTcpServer()
{}

void CmdTcpServer::incomingConnection(qintptr socketDescriptor)
{
    // 如果已有客户端在线，则拒绝新连接
    if(currentClient && currentClient->state() != QAbstractSocket::UnconnectedState)
    {
        QTcpSocket temp;
        temp.setSocketDescriptor(socketDescriptor);
        DIY_LOG(LOG_INFO, QString("A new connection req from %1:%2, but server is working, "
                                  "so refuse it.").arg(temp.peerAddress().toString())
                                                  .arg(temp.peerPort()));
        temp.disconnectFromHost();  // 主动断开
        return;
    }

    QTcpSocket *clientSocket = new QTcpSocket(this);
    if (!clientSocket->setSocketDescriptor(socketDescriptor)) {
        clientSocket->deleteLater();
        return;
    }

    currentClient = clientSocket;
    // 当客户端断开连接时，发信号 + 清理
    connect(clientSocket, &QTcpSocket::disconnected, this,
            [this, clientSocket]()
            {
                emit rmt_client_disconnected(clientSocket);
                clientSocket->deleteLater();  // 自动释放
                currentClient = nullptr;
            });

    connect(clientSocket, &QTcpSocket::stateChanged, this,
            [this](QAbstractSocket::SocketState socketState)
            {
                emit tcp_server_conn_state_changed(socketState);
            });

    emit rmt_client_connected(clientSocket);
}
