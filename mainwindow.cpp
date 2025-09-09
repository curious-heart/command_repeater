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
    , ui(new Ui::MainWindow), m_cfg_recorder(this)
{
    qRegisterMetaType<cmd_id_e_t>("cmd_id_e_t");
    qRegisterMetaType<test_finish_reason_e_t>("test_finish_reason_e_t");

    ui->setupUi(this);
    ui->completeCmdCycleChkbox->setChecked(true);

    set_ctrls_attr();

    m_rec_ui_cfg_fin.clear();
    m_rec_ui_cfg_fout << ui->cmd1ContentLEdit << ui->cmd2ContentLEdit;

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

    udpSocket = new QUdpSocket(this);

    refresh_ctrls_display();

    m_init_ok = true;
}

MainWindow::~MainWindow()
{
    m_cfg_recorder.record_ui_configs(this);

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

    ui->startTestPBtn->setEnabled(!m_in_test);
    ui->stopTestPBtn->setEnabled(m_in_test);
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
    }
    ++m_repeat_idx;

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

    udpSocket->writeDatagram(cmd, QHostAddress(m_rmt_ip), m_rmt_port);

    QString log_str = QString("send %1 (%2) to %3:%4: ")
                                .arg(VALID_CMD_ID(cmd_id) ? g_test_cmd_id_str[cmd_id]
                                                            : g_str_unknown_cmd)
                                .arg(m_repeat_idx + 1)
                                .arg(m_rmt_ip).arg(m_rmt_port);
    log_str += cmd.toHex(' ').rightJustified(2, '0').toUpper();

    DIY_LOG(LOG_INFO, log_str);
}

void MainWindow::cmd_timer_sig_hdlr()
{
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

void MainWindow::test_finished_sig_hdlr(test_finish_reason_e_t reason)
{
    QString str = QString("%1: %2\n").arg(g_str_test_finished,
                                VALID_FINISH_REASON(reason) ? g_test_finish_reason_str[reason] :
                                                              g_str_unknown_reason);
    str += QString("Total send %1 cycles.").arg(m_repeat_idx);
    DIY_LOG(LOG_INFO, str);

    reset_test();

    refresh_ctrls_display();

    QMessageBox::information(this, "", str);
}
