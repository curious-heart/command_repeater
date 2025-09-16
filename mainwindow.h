#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QUdpSocket>
#include <QTcpSocket>
#include <QThread>

#include "config_recorder/uiconfigrecorder.h"
#include "common_tools/common_macros.h"
#include "sysconfigs/sysconfigs.h"
#include "pingthread.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

#define CMD_ID_E_LIST \
    ENUM_NAME_DEF(CMD_NONE, =0) \
    ENUM_NAME_DEF(CMD_1) \
    ENUM_NAME_DEF(CMD_2)
typedef enum
{
    CMD_ID_E_LIST
}cmd_id_e_t;
Q_DECLARE_METATYPE(cmd_id_e_t)
#define VALID_CMD_ID(e) ((CMD_1 <= (e)) && ((e) <= CMD_2))

#define TEST_FINISH_REASON_E_LIST \
    ENUM_NAME_DEF(FINISH_NONE) \
    ENUM_NAME_DEF(FINISH_BY_USER) \
    ENUM_NAME_DEF(FINISH_BY_COUNTER) \
    ENUM_NAME_DEF(FINISH_DUE_TO_NETWORK_ERROR) \
    ENUM_NAME_DEF(FINISH_ON_APP_EXIT) \
    ENUM_NAME_DEF(FINISH_REASON_CNT)
typedef enum
{
    TEST_FINISH_REASON_E_LIST
}test_finish_reason_e_t;
Q_DECLARE_METATYPE(test_finish_reason_e_t)
#define VALID_FINISH_REASON(e) ((FINISH_NONE <= (e)) && ((e) < FINISH_REASON_CNT))

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    bool m_init_ok;
    QString m_init_err_str;

private slots:
    void on_repeatInfiChkbox_toggled(bool checked);

    void on_startTestPBtn_clicked();

    void on_stopTestPBtn_clicked();

    void onSocketConnected();
    void onSocketDisConnected();
    void onSocketError(QAbstractSocket::SocketError socketError);
    void onStateChanged(QAbstractSocket::SocketState socketState);

private:
    Ui::MainWindow *ui;
    UiConfigRecorder m_cfg_recorder;
    qobj_ptr_set_t m_rec_ui_cfg_fin, m_rec_ui_cfg_fout;

    QString m_rmt_ip;
    quint16 m_rmt_port;
    int m_repeat_cnt;
    double m_cmd1_dura_s, m_cmd2_dura_s;

    int m_repeat_idx;
    cmd_id_e_t m_curr_cmd;
    bool m_in_test;
    QTimer m_cmd_timer;

    QUdpSocket * udpSocket = nullptr;
    QTcpSocket * tcpSocket = nullptr;

    PingThread * m_ping_th;
    QThread *m_ping_th_hdlr;

    void set_ctrls_attr();
    void check_and_set_ctrl_vals();
    void refresh_ctrls_display();
    void reset_test();
    void send_cmd(cmd_id_e_t cmd_id);

    bool update_test_params_on_ui(bool init = false, QString *ret_err_str = nullptr);
    void display_info(QString info_str, bool no_prefix = false);

    void tcp_conn();
    void tcp_disconn();

signals:
    void test_finished_sig(test_finish_reason_e_t reason, bool quiet = false);
    void start_ping_sig(const QString ip, int int_between_s_r = g_def_ping_int_between_s_r,
                        int waitTimeSec = g_def_ping_wait_dura_s,
                        int int_between_r_s = g_def_ping_int_between_r_s,
                        int maxMissCount = g_def_ping_miss_count,
                const QByteArray data = QByteArray(g_def_ping_data, qstrlen(g_def_ping_data)));
    void stop_ping_sig();

private slots:
    void cmd_timer_sig_hdlr();
    void test_finished_sig_hdlr(test_finish_reason_e_t reason, bool quiet = false);
    void on_clrDispPBtn_clicked();
    void target_unavaliable_sig_hdlr();
    void on_tcpConnPBtn_clicked();
};
#endif // MAINWINDOW_H
