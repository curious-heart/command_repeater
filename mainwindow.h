#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QUdpSocket>

#include "config_recorder/uiconfigrecorder.h"
#include "common_tools/common_macros.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

typedef enum
{
    CMD_NONE = 0,
    CMD_1,
    CMD_2,
}cmd_id_e_t;
Q_DECLARE_METATYPE(cmd_id_e_t)
#define VALID_CMD_ID(e) ((CMD_1 <= (e)) && ((e) <= CMD_2))

#define TEST_FINISH_REASON_E_LIST \
    ENUM_NAME_DEF(FINISH_BY_USER) \
    ENUM_NAME_DEF(FINISH_BY_COUNTER)
typedef enum
{
    TEST_FINISH_REASON_E_LIST
}test_finish_reason_e_t;
Q_DECLARE_METATYPE(test_finish_reason_e_t)
#define VALID_FINISH_REASON(e) ((FINISH_BY_USER <= (e)) && ((e) <= FINISH_BY_COUNTER))

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

    QUdpSocket *udpSocket;

    void set_ctrls_attr();
    void check_and_set_ctrl_vals();
    void refresh_ctrls_display();
    void reset_test();
    void send_cmd(cmd_id_e_t cmd_id);

    bool update_test_params_on_ui(bool init = false);

signals:
    void test_finished_sig(test_finish_reason_e_t reason);

private slots:
    void cmd_timer_sig_hdlr();
    void test_finished_sig_hdlr(test_finish_reason_e_t reason);
};
#endif // MAINWINDOW_H
