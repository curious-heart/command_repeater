#include "mainwindow.h"
#include "version_def/version_def.h"

#include <QApplication>
#include <QThread>
#include <QString>
#include <QMessageBox>
#include <QScreen>

#include "common_tools/common_tool_func.h"
#include "logger/logger.h"
#include "sysconfigs/sysconfigs.h"
int main(int argc, char *argv[])
{
    if(QT_VERSION>=QT_VERSION_CHECK(5,6,0))
            QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

    /*init define app.*/
    QApplication a(argc, argv);
    // 设置全局样式表
    a.setStyleSheet(
        "QLineEdit[readOnly=\"true\"] { "
        "  background-color: #f5f5f5; "
        "  color: black; "
        "  border: 1px solid #cccccc; "
        "} "
    );

    /*initialization: start log thread. Now use the default log-level defined in logger mode.*/
    QThread th;
    int ret;
    start_log_thread(th);

    /*initialization: load configs.*/
    QString ret_str;
    bool log_cfg_ret = fill_sys_configs(&ret_str);
    if(!log_cfg_ret)
    {
        end_log_thread(th);

        QMessageBox::critical(nullptr, "", ret_str);
        return -1;
    }
    //use the log level defined in config file.
    update_log_level((LOG_LEVEL)(g_sys_configs_block.log_level));

    /*create main window.*/
    QString title_str = QString("%1 %2").arg(a.applicationName(), APP_VER_STR);
    MainWindow w;
    if(!w.m_init_ok)
    {
        end_log_thread(th);

        QMessageBox::critical(nullptr, "", w.m_init_err_str);
        return -1;
    }

    w.setWindowTitle(title_str);

    w.show();

    ret = a.exec();

    end_log_thread(th);

    if((int)APP_EXIT_APP_POWER_OFF == ret || (int)APP_EXIT_HD_POWER_OFF == ret)
    {
        //power off system
        shutdown_system();
    }

    return ret;
}
