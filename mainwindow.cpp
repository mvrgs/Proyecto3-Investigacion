#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QLineEdit>
#include <QPushButton>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QDebug>
#include <QRandomGenerator>
#include <iostream>
#include <iomanip>
#include <openssl/aes.h>
#include <openssl/rand.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
    ui(new Ui::MainWindow),
    timer(new QElapsedTimer)
{
    ui->setupUi(this);

    // Establecer la ruta del archivo CSV
    csvFilePath = "usuarios.csv";

    hashCsvFilePath = "usuariosHash.csv";

    aesCsvFilePath = "usuariosAES.csv";



    // Conectar el evento del botón Agregar con la función correspondiente
    connect(ui->agregarButton, &QPushButton::clicked, this, &MainWindow::on_agregarButton_clicked);

    // Inicializar el temporizador
    timer->start();
}

void MainWindow::on_agregarButton_clicked()
{
    // Obtener datos de los campos de entrada
    QString nombre = ui->nameInput->text();
    QString lugar = ui->placeInput->text();
    QString cedula = ui->cedulaInput->text();
    QString idEmpleado = ui->idInput->text();
    QString telefono = ui->numberInput->text();

    // Comprobar si los campos están vacíos
    if (nombre.trimmed().isEmpty() || lugar.trimmed().isEmpty() || cedula.trimmed().isEmpty() || idEmpleado.trimmed().isEmpty() || telefono.trimmed().isEmpty())
    {
        QMessageBox::warning(this, "Espacios Vacíos", "Por favor, complete todos los espacios requeridos.");
            return;
    }

    // Crear una línea de texto con los datos separados por comas
    QString data = QString("%1,%2,%3,%4,%5").arg(nombre, lugar, cedula, idEmpleado, telefono);

    // Escribir en el archivo CSV
    writeToCsv(data);

    // Limpiar los campos de entrada después de agregar
    ui->nameInput->clear();
    ui->placeInput->clear();
    ui->cedulaInput->clear();
    ui->idInput->clear();
    ui->numberInput->clear();

    QMessageBox::information(this, "Éxito", "Usuario agregado correctamente.");
}

void MainWindow::writeToCsv(const QString &data)
{
    // Obtener datos de los campos de entrada
    QString nombre = ui->nameInput->text();

    // Iniciar el temporizador para medir el tiempo de hashing y cifrado con AES
    qint64 hashTimeStart = timer->nsecsElapsed();
    qint64 aesTimeStart;

    // Calcular el hash de cada valor individual
    QByteArray hashedLugar = QCryptographicHash::hash(ui->placeInput->text().toUtf8(), QCryptographicHash::Md5);
    QByteArray hashedCedula = QCryptographicHash::hash(ui->cedulaInput->text().toUtf8(), QCryptographicHash::Md5);
    QByteArray hashedIdEmpleado = QCryptographicHash::hash(ui->idInput->text().toUtf8(), QCryptographicHash::Md5);
    QByteArray hashedTelefono = QCryptographicHash::hash(ui->numberInput->text().toUtf8(), QCryptographicHash::Md5);

    // Detener el temporizador y calcular el tiempo de hashing
    qint64 hashTimeElapsed = timer->nsecsElapsed() - hashTimeStart;
    qDebug() << "Tiempo de hashing: " << hashTimeElapsed << " nanosegundos";

    // Convertir los hashes a cadenas hexadecimales
    QString hashedLugarHex = QString(hashedLugar.toHex());
    QString hashedCedulaHex = QString(hashedCedula.toHex());
    QString hashedIdEmpleadoHex = QString(hashedIdEmpleado.toHex());
    QString hashedTelefonoHex = QString(hashedTelefono.toHex());

    // Generar una clave y un IV aleatorio para AES
    QByteArray aesKey = QByteArray(16, 0);
    QByteArray aesIV = QByteArray(16, 0);
    RAND_bytes(reinterpret_cast<unsigned char *>(aesKey.data()), aesKey.size());
    RAND_bytes(reinterpret_cast<unsigned char *>(aesIV.data()), aesIV.size());

    // Iniciar el temporizador para medir el tiempo de cifrado con AES
    aesTimeStart = timer->nsecsElapsed();

    // Cifrar los datos originales con AES
    QByteArray encryptedData = encryptAES(data.toUtf8(), aesKey, aesIV);

    // Detener el temporizador y calcular el tiempo de cifrado con AES
    qint64 aesTimeElapsed = timer->nsecsElapsed() - aesTimeStart;
    qDebug() << "Tiempo de cifrado con AES: " << aesTimeElapsed << " nanosegundos";

    // Abrir el archivo CSV en modo de escritura
    QFile csvFile(csvFilePath);
    if (csvFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
    {
            QTextStream csvStream(&csvFile);

            // Escribir la línea de datos originales en el archivo CSV
            csvStream << nombre << ","
                      << ui->placeInput->text() << ","
                      << ui->cedulaInput->text() << ","
                      << ui->idInput->text() << ","
                      << ui->numberInput->text() << endl;

            // Cerrar el archivo CSV
            csvFile.close();
    }
    else
    {
            QMessageBox::critical(this, "Error", "No se pudo abrir el archivo CSV.");
    }

    // Abrir el archivo CSV en modo de escritura para datos encriptados
    QFile hashCsvFile(hashCsvFilePath);
    if (hashCsvFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
    {
            QTextStream encryptedCsvStream(&hashCsvFile);

            // Escribir la línea de datos encriptados en el archivo CSV
            encryptedCsvStream << nombre << ","
                               << hashedLugarHex << ","
                               << hashedCedulaHex << ","
                               << hashedIdEmpleadoHex << ","
                               << hashedTelefonoHex << ","
                               << QByteArray(encryptedData.toHex()) << endl;

            // Cerrar el archivo CSV para datos encriptados
            hashCsvFile.close();
    }
    else
    {
            QMessageBox::critical(this, "Error", "No se pudo abrir el archivo CSV para datos encriptados.");
    }

    // Obtener los datos individuales encriptados con AES
    QByteArray encryptedLugar = encryptAES(ui->placeInput->text().toUtf8(), aesKey, aesIV);
    QByteArray encryptedCedula = encryptAES(ui->cedulaInput->text().toUtf8(), aesKey, aesIV);
    QByteArray encryptedIdEmpleado = encryptAES(ui->idInput->text().toUtf8(), aesKey, aesIV);
    QByteArray encryptedTelefono = encryptAES(ui->numberInput->text().toUtf8(), aesKey, aesIV);

    // Abrir el archivo CSV en modo de escritura para datos encriptados con AES
    QFile aesCsvFile(aesCsvFilePath);
    if (aesCsvFile.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
    {
            QTextStream aesCsvStream(&aesCsvFile);

            // Escribir la línea de datos encriptados en el archivo CSV
            aesCsvStream << nombre << ","
                         << QByteArray(encryptedLugar.toHex()) << ","
                         << QByteArray(encryptedCedula.toHex()) << ","
                         << QByteArray(encryptedIdEmpleado.toHex()) << ","
                         << QByteArray(encryptedTelefono.toHex()) << "\n";

            // Cerrar el archivo CSV para datos encriptados con AES
            aesCsvFile.close();
    }
    else
    {
            QMessageBox::critical(this, "Error", "No se pudo abrir el archivo CSV para datos encriptados con AES.");
    }
}

QByteArray MainWindow::encryptAES(const QByteArray &data, const QByteArray &key, const QByteArray &iv)
{
    QByteArray encryptedData;

    AES_KEY aesKey;
    if (AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.constData()), 128, &aesKey) != 0)
    {
        qDebug() << "Error al establecer la clave de cifrado AES.";
        return encryptedData;
    }

    // Tamaño del bloque AES
    size_t blockSize = AES_BLOCK_SIZE;

    // Asegurar que los datos sean múltiplos del tamaño del bloque
    size_t paddedSize = ((data.size() + blockSize - 1) / blockSize) * blockSize;
    QByteArray paddedData = data.leftJustified(paddedSize, 0);

    // Reservar espacio para los datos cifrados
    encryptedData.resize(paddedSize);

    // Copiar el contenido de iv a un nuevo QByteArray no constante
    QByteArray mutableIV = iv;

    // Cifrar los datos
    AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(paddedData.constData()),
                    reinterpret_cast<unsigned char *>(encryptedData.data()),
                    paddedSize, &aesKey,
                    reinterpret_cast<unsigned char *>(mutableIV.data()), AES_ENCRYPT);

    return encryptedData;
}


MainWindow::~MainWindow()
{
    delete ui;
    delete timer;
}
