#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QElapsedTimer>


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    QByteArray encryptAES(const QByteArray &data, const QByteArray &key, const QByteArray &iv);



private slots:
    void on_agregarButton_clicked();
    void writeToCsv(const QString &data);



private:
    Ui::MainWindow *ui;
    QString csvFilePath;         // Ruta del archivo CSV para los datos originales
    QString hashCsvFilePath; //Ruta del archivo CSV para los datos encriptados con hash
    QString aesCsvFilePath;
    QElapsedTimer* timer;

};

#endif // MAINWINDOW_H
