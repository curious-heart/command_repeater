#pragma once

#include <QTcpServer>
#include <QTcpSocket>

class CmdTcpServer : public QTcpServer
{
    Q_OBJECT

public:
    explicit CmdTcpServer(QObject *parent = nullptr);
    ~CmdTcpServer();

    QTcpSocket *currentClient = nullptr;

signals:
    void rmt_client_connected(QTcpSocket *clientSocket);
    void rmt_client_disconnected(QTcpSocket *clientSocket);
    void tcp_server_conn_state_changed(QAbstractSocket::SocketState socketState);

protected:

    void incomingConnection(qintptr socketDescriptor) override;
};
