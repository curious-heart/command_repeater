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

void set_app_font_size()
{
    static qreal ls_base_scale_factor = 2;

    QScreen *screen = QGuiApplication::primaryScreen();
    QSize scrn_size = screen->size();
    int scrn_width_px = scrn_size.width();
    int scrn_height_px = scrn_size.height();
    qreal dpiX = screen->logicalDotsPerInchX();
    qreal dpiY = screen->logicalDotsPerInchY();

    qreal phy_dpiX = screen->logicalDotsPerInchX();
    qreal phy_dpiY = screen->logicalDotsPerInchY();

    qreal scale_factor = screen->devicePixelRatio();

    QString scrn_info_str;
    scrn_info_str += QString("scrn width in px: %1, heigh in px: %2\n").arg(scrn_width_px).arg(scrn_height_px);
    scrn_info_str += QString("scrn logical dpi X:%1, Y: %2\n").arg(dpiX).arg(dpiY);
    scrn_info_str += QString("scrn physical dpi X:%1, Y: %2\n").arg(phy_dpiX).arg(phy_dpiY);
    scrn_info_str += QString("scale factor: %1\n").arg(scale_factor);

    DIY_LOG(LOG_INFO, scrn_info_str);

    QFont app_font = QApplication::font();
    qreal ori_app_font_pt_size = app_font.pointSizeF();
    qreal new_app_font_pt_size = ori_app_font_pt_size * ls_base_scale_factor / scale_factor;
    app_font.setPointSizeF(new_app_font_pt_size);
    QApplication::setFont(app_font);
    DIY_LOG(LOG_INFO, QString("ori app font point size is %1, new size is %2\n")
                        .arg(ori_app_font_pt_size).arg(new_app_font_pt_size));
}

int main(int argc, char *argv[])
{
    if(QT_VERSION>=QT_VERSION_CHECK(5,6,0))
            QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

    /*init define app.*/
    QApplication a(argc, argv);
    // 设置全局样式表
    a.setStyleSheet(
        "QLineEdit[readOnly=\"true\"], "
        "QTextEdit[readOnly=\"true\"], "
        "QPlainTextEdit[readOnly=\"true\"] "
        " { "
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

    set_app_font_size();

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
