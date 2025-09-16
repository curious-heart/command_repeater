#include <QMessageBox>

#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "literal_strings/literal_strings.h"
#include "common_tools/common_tool_func.h"
#include "sysconfigs/sysconfigs.h"
#include "logger/logger.h"

#undef ENUM_NAME_DEF
#define ENUM_NAME_DEF(e, ...) #e,

const char* g_test_cmd_id_str[] = { CMD_ID_E_LIST };
const char* g_test_finish_reason_str[] = { TEST_FINISH_REASON_E_LIST };

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_init_ok(false)
    , ui(new Ui::MainWindow), m_cfg_recorder(this),
      m_ping_th(nullptr), m_ping_th_hdlr(nullptr)
{
    qRegisterMetaType<cmd_id_e_t>("cmd_id_e_t");
    qRegisterMetaType<test_finish_reason_e_t>("test_finish_reason_e_t");

    ui->setupUi(this);
    ui->completeCmdCycleChkbox->setChecked(true);

    set_ctrls_attr();

    m_rec_ui_cfg_fin.clear();
    m_rec_ui_cfg_fout << ui->cmd1ContentLEdit << ui->cmd2ContentLEdit
                      << ui->infoDispEdit;

    //load ui settings saved last time.
    m_cfg_recorder.load_configs_to_ui(this, m_rec_ui_cfg_fin, m_rec_ui_cfg_fout);

    //check values.
    check_and_set_ctrl_vals();

    m_cmd_timer.setSingleShot(true);
    connect(&m_cmd_timer, &QTimer::timeout, this, &MainWindow::cmd_timer_sig_hdlr,
            Qt::QueuedConnection);

    connect(this, &MainWindow::test_finished_sig,
            this, &MainWindow::test_finished_sig_hdlr, Qt::QueuedConnection);

    reset_test();

    if(g_prot_udp_str == g_sys_configs_block.rmt_ip_port.prot)
    {
        udpSocket = new QUdpSocket(this);
    }
    else
    {
        tcpSocket = new QTcpSocket(this);
        connect(tcpSocket, &QTcpSocket::connected, this, &MainWindow::onSocketConnected);
        connect(tcpSocket, &QTcpSocket::disconnected, this, &MainWindow::onSocketDisConnected);
        connect(tcpSocket, &QTcpSocket::stateChanged, this, &MainWindow::onStateChanged);
        connect(tcpSocket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred),
                this, &MainWindow::onSocketError);
    }

    refresh_ctrls_display();

    if((g_prot_udp_str == g_sys_configs_block.rmt_ip_port.prot)
            && g_sys_configs_block.ping_params.check_ping)
    {
        m_ping_th = new PingThread();
        if(m_ping_th->m_init_ok)
        {
            m_ping_th_hdlr = new QThread(this);
            m_ping_th->moveToThread(m_ping_th_hdlr);
            connect(m_ping_th_hdlr, &QThread::finished, m_ping_th, &QObject::deleteLater);

            connect(m_ping_th, &PingThread::target_unavaliable_sig,
                    this, &MainWindow::target_unavaliable_sig_hdlr, Qt::QueuedConnection);

            connect(this, &MainWindow::start_ping_sig, m_ping_th, &PingThread::start_ping_hdlr,
                    Qt::QueuedConnection);
            connect(this, &MainWindow::stop_ping_sig, m_ping_th, &PingThread::stop_ping_hdlr,
                    Qt::QueuedConnection);

            m_ping_th_hdlr->start();
        }
        else
        {
            delete m_ping_th;
            m_ping_th = nullptr;
            DIY_LOG(LOG_WARN, "Ping thread init fails");
        }
    }

    m_init_ok = true;
}

MainWindow::~MainWindow()
{
    m_cfg_recorder.record_ui_configs(this);

    if(m_in_test)
    {
        test_finished_sig_hdlr(FINISH_ON_APP_EXIT, true);
    }

    if(tcpSocket)
    {
        tcp_disconn();
    }

    if(m_ping_th_hdlr)
    {
        m_ping_th_hdlr->quit();
        m_ping_th_hdlr->wait();
        m_ping_th_hdlr->deleteLater();
        m_ping_th_hdlr = nullptr;
    }

    delete ui;
}


void MainWindow::on_repeatInfiChkbox_toggled(bool checked)
{
    ui->repeatCntSpinbox->setEnabled(!checked);
}


void MainWindow::refresh_ctrls_display()
{
    ui->rmtIPLEdit->setEnabled(!m_in_test);
    ui->rmtPortLEdit->setEnabled(!m_in_test);
    ui->repeatCntSpinbox->setEnabled(!m_in_test && !ui->repeatInfiChkbox->isChecked());
    ui->repeatInfiChkbox->setEnabled(!m_in_test);
    ui->cmd1DuraLEdit->setEnabled(!m_in_test);
    ui->cmd2DuraLEdit->setEnabled(!m_in_test);

    bool use_tcp = (g_prot_tcp_str == g_sys_configs_block.rmt_ip_port.prot);
    ui->tcpConnPBtn->setVisible(use_tcp);
    if(use_tcp)
    {
        bool send_en = false;
        if(!tcpSocket)
        {
            ui->tcpConnPBtn->setEnabled(false);
        }
        else
        {
            ui->tcpConnPBtn->setEnabled(true);
            if(tcpSocket->state() == QAbstractSocket::UnconnectedState)
            {
                ui->tcpConnPBtn->setText(g_str_connected);
            }
            else if(tcpSocket->state() == QAbstractSocket::ConnectedState)
            {
                ui->tcpConnPBtn->setText(g_str_disconnected);
                send_en = true;
            }
            else
            {
                ui->tcpConnPBtn->setEnabled(false);
            }

        }
        send_en = send_en && !m_in_test;
        ui->startTestPBtn->setEnabled(send_en);
        ui->stopTestPBtn->setEnabled(m_in_test);
    }
    else
    {
        ui->startTestPBtn->setEnabled(!m_in_test);
        ui->stopTestPBtn->setEnabled(m_in_test);
    }
}

void MainWindow::check_and_set_ctrl_vals()
{
    update_test_params_on_ui(true);

    ui->cmd1ContentLEdit->setText(g_sys_configs_block.cmd_blk.cmd1_content.toHex(' ')
                                  .rightJustified(2, '0').toUpper());

    ui->cmd2ContentLEdit->setText(g_sys_configs_block.cmd_blk.cmd2_content.toHex(' ')
                                  .rightJustified(2, '0').toUpper());
}

void MainWindow::set_ctrls_attr()
{
    ui->repeatCntSpinbox->setRange(1, INT_MAX);

    ui->cmd1ContentLEdit->setReadOnly(true);
    ui->cmd2ContentLEdit->setReadOnly(true);

    QString cmd_n = ui->cmd1Lbl->text();
    ui->cmd1Lbl->setText(cmd_n + g_sys_configs_block.cmd_blk.cmd1_name);
    cmd_n = ui->cmd2Lbl->text();
    ui->cmd2Lbl->setText(cmd_n + g_sys_configs_block.cmd_blk.cmd2_name);
}

bool MainWindow::update_test_params_on_ui(bool init, QString * ret_err_str)
{
    bool ret = true;
    QString err_str;

    if(!ip_addr_valid(ui->rmtIPLEdit->text()))
    {
        if(init)
        {
            m_rmt_ip = g_sys_configs_block.rmt_ip_port.ip;
            ui->rmtIPLEdit->setText(m_rmt_ip);
        }
        else
        {
            ret = false;
            err_str += QString((err_str.isEmpty() ? "" : "\n")) + g_str_invalid_ip_addr;
        }
    }
    else
    {
        m_rmt_ip = ui->rmtIPLEdit->text();
    }

    bool tr_ret;
    int tmp_port = ui->rmtPortLEdit->text().toInt(&tr_ret);
    if(!tr_ret || !g_ip_port_ranger.range_check(tmp_port))
    {
        if(init)
        {
            m_rmt_port = g_sys_configs_block.rmt_ip_port.port;
            ui->rmtPortLEdit->setText(QString::number(m_rmt_port));
        }
        else
        {
            ret = false;
            err_str += QString((err_str.isEmpty() ? "" : "\n")) + g_str_invalid_port_number;
        }
    }
    else
    {
        m_rmt_port = (quint16)tmp_port;
    }

    m_repeat_cnt = ui->repeatCntSpinbox->value();

    double * val_ptrs[] = {&m_cmd1_dura_s, &m_cmd2_dura_s};
    QLineEdit * line_edits[] = {ui->cmd1DuraLEdit, ui->cmd2DuraLEdit};
    double def_vals[] = {g_sys_configs_block.cmd_blk.cmd1_dura_s, g_sys_configs_block.cmd_blk.cmd2_dura_s};
    for(size_t i = 0; i < ARRAY_COUNT(val_ptrs); ++i)
    {
        double v_from_str = line_edits[i]->text().toDouble(&tr_ret);
        if(!tr_ret)
        {
            if(init)
            {
                *(val_ptrs)[i] = def_vals[i];
                line_edits[i]->setText(QString::number(def_vals[i]));
            }
            else
            {
                ret = false;
                err_str += QString((err_str.isEmpty() ? "" : "\n"))
                            + QString("%1%2").arg(g_str_invalid_dura_value).arg(i);
            }
        }
        else
        {
            *(val_ptrs[i]) = v_from_str;
        }

    }

    if(ret_err_str) *ret_err_str = err_str;
    return ret;
}

void MainWindow::on_startTestPBtn_clicked()
{
    QString err_str;
    if(!update_test_params_on_ui(false, &err_str))
    {
        QMessageBox::critical(this, "", err_str);
        return;
    }

    m_repeat_idx = 0;
    m_curr_cmd = CMD_2;
    m_in_test = true;

    refresh_ctrls_display();

    if(m_ping_th) emit start_ping_sig(m_rmt_ip, g_sys_configs_block.ping_params.ping_int_between_s_r,
                                      g_sys_configs_block.ping_params.ping_wait_dura_s,
                                      g_sys_configs_block.ping_params.ping_int_between_r_s,
                                      g_sys_configs_block.ping_params.ping_miss_count,
                                      g_sys_configs_block.ping_params.ping_data);

    m_cmd_timer.start(0);

    m_cfg_recorder.record_ui_configs(this);
}

void MainWindow::reset_test()
{
    m_cmd_timer.stop();

    m_in_test = false;
    m_curr_cmd = CMD_NONE;
    m_repeat_idx = 0;
}

void MainWindow::on_stopTestPBtn_clicked()
{
    if(CMD_1 == m_curr_cmd && ui->completeCmdCycleChkbox->isChecked())
    {
        DIY_LOG(LOG_INFO, "Complete cmd cycle, send CMD_2");
        send_cmd(CMD_2);
        ++m_repeat_idx;
    }

    test_finished_sig_hdlr(FINISH_BY_USER);
}

void MainWindow::send_cmd(cmd_id_e_t cmd_id)
{
    if(!VALID_CMD_ID(cmd_id))
    {
        DIY_LOG(LOG_ERROR, QString("Invalid cmd_id: %1").arg((int)cmd_id));
        return;
    }
    QByteArray cmd = (CMD_1 == cmd_id) ? g_sys_configs_block.cmd_blk.cmd1_content :
                                         g_sys_configs_block.cmd_blk.cmd2_content;

    if(g_prot_tcp_str == g_sys_configs_block.rmt_ip_port.prot)
    {
        tcpSocket->write(cmd);
        tcpSocket->flush();
    }
    else
    {
        udpSocket->writeDatagram(cmd, QHostAddress(m_rmt_ip), m_rmt_port);
    }

    QString log_str = QString("send %1 (%2) to %3:%4: ")
                                .arg(VALID_CMD_ID(cmd_id) ? g_test_cmd_id_str[cmd_id]
                                                            : g_str_unknown_cmd)
                                .arg(m_repeat_idx + 1)
                                .arg(m_rmt_ip).arg(m_rmt_port);
    log_str += cmd.toHex(' ').rightJustified(2, '0').toUpper();

    DIY_LOG(LOG_INFO, log_str);

    display_info(log_str);
}

void MainWindow::cmd_timer_sig_hdlr()
{
    if(!m_in_test)
    {
        emit test_finished_sig(FINISH_NONE, true);
        return;
    }

    bool go_on = ui->repeatInfiChkbox->isChecked() || (m_repeat_idx < m_repeat_cnt);

    if(!go_on)
    {
        emit test_finished_sig(FINISH_BY_COUNTER);
        return;
    }

    int timer_dura_ms;
    if(CMD_1 == m_curr_cmd)
    {
        m_curr_cmd = CMD_2;
        timer_dura_ms = (int)(m_cmd2_dura_s * 1000);
    }
    else
    {
        m_curr_cmd = CMD_1;
        timer_dura_ms = (int)(m_cmd1_dura_s * 1000);
    }
    send_cmd(m_curr_cmd);
    if(CMD_2 == m_curr_cmd)
    {
        ++m_repeat_idx;
    }

    go_on = (CMD_1 == m_curr_cmd) || ui->repeatInfiChkbox->isChecked() || (m_repeat_idx < m_repeat_cnt);
    if(go_on)
    {
        m_cmd_timer.start(timer_dura_ms);
    }
    else
    {
        emit test_finished_sig(FINISH_BY_COUNTER);
    }
}

void MainWindow::test_finished_sig_hdlr(test_finish_reason_e_t reason, bool quiet)
{
    QString str = QString("%1: %2\n").arg(g_str_test_finished,
                                VALID_FINISH_REASON(reason) ? g_test_finish_reason_str[reason] :
                                                              g_str_unknown_reason);
    str += QString("Total send %1 cycles.").arg(m_repeat_idx);
    DIY_LOG(LOG_INFO, str);

    if(!quiet)
    {
        display_info("", true);
        str += "\n--------------------------------";

        display_info(str);
    }

    if(g_prot_tcp_str == g_sys_configs_block.rmt_ip_port.prot)
    {
        tcp_disconn();
    }

    if(m_ping_th_hdlr) emit stop_ping_sig();

    reset_test();

    refresh_ctrls_display();

    if(!quiet) QMessageBox::information(this, "", str);
}

void MainWindow::on_clrDispPBtn_clicked()
{
    ui->infoDispEdit->clear();
}

void MainWindow::display_info(QString info_str, bool no_prefix )
{
    QString prefix_str = common_tool_get_curr_dt_str("-", " ", ":") + " ";
    QString disp_str = no_prefix ? info_str : prefix_str + info_str;
    ui->infoDispEdit->append(disp_str);
}

void MainWindow::target_unavaliable_sig_hdlr()
{
    test_finished_sig_hdlr(FINISH_DUE_TO_NETWORK_ERROR);
}

void MainWindow::onSocketConnected()
{
    refresh_ctrls_display();

    QString disp_str = "tcp connected.";
    ui->infoDispEdit->append(disp_str);
    DIY_LOG(LOG_INFO, disp_str)
}

void MainWindow::onSocketDisConnected()
{
    refresh_ctrls_display();

    QString disp_str = "tcp disconnected.";
    ui->infoDispEdit->append(disp_str);
    DIY_LOG(LOG_INFO, disp_str);

    test_finished_sig_hdlr(FINISH_DUE_TO_NETWORK_ERROR);

}

void MainWindow::onStateChanged(QAbstractSocket::SocketState socketState)
{
    refresh_ctrls_display();

    QString disp_str = QString("tcp state changed to %1").arg(socketState);
    ui->infoDispEdit->append(disp_str);
    DIY_LOG(LOG_INFO, disp_str)
}

void MainWindow::onSocketError(QAbstractSocket::SocketError socketError)
{
    Q_UNUSED(socketError)

    refresh_ctrls_display();

    QString disp_str = QString("tcp error: %1").arg(tcpSocket->errorString());
    ui->infoDispEdit->append(disp_str);
    DIY_LOG(LOG_ERROR, disp_str)
}

void MainWindow::tcp_conn()
{
    if(!tcpSocket) return;

    QAbstractSocket::SocketState sock_st = tcpSocket->state();
    if(QAbstractSocket::UnconnectedState == sock_st)
    {
        tcpSocket->connectToHost(m_rmt_ip, m_rmt_port);
    }
    else
    {
        DIY_LOG(LOG_INFO, QString("cant't connt tcp sock_st: %2").arg(sock_st));
    }
}

void MainWindow::tcp_disconn()
{
    if(tcpSocket && (tcpSocket->state() == QAbstractSocket::ConnectedState))
    {
        tcpSocket->disconnectFromHost();  // 发起断开
        // 如果服务器没有立即关闭连接，可以调用 waitForDisconnected
        if (!tcpSocket->waitForDisconnected(3000))
        { // 最多等待3秒
            DIY_LOG(LOG_WARN, "force tcp abort");
            tcpSocket->abort(); // 强制断开
        }
    }
}

void MainWindow::on_tcpConnPBtn_clicked()
{
    if(!tcpSocket)
    {
        DIY_LOG(LOG_ERROR, "tcpSocket is NULL.");
        return;
    }
    QAbstractSocket::SocketState sock_st = tcpSocket->state();
    DIY_LOG(LOG_INFO, QString("TCP st: %1").arg(sock_st));
    if(QAbstractSocket::UnconnectedState == sock_st)
    {
        tcp_conn();
    }
    else
    {
        tcp_disconn();
    }
    refresh_ctrls_display();
}

